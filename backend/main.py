from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, validator
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from jose import JWTError, jwt
import csv
import logging
from pathlib import Path
import os
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse

# Configuração de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configurações
SECRET_KEY = "monks-case-secret-key-2025"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24
MAX_RECORDS_PER_REQUEST = 1000

app = FastAPI(title="Monks Marketing Dashboard API", version="1.0.0")

# Mount the frontend directory as static files at /static
frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../frontend"))
app.mount("/static", StaticFiles(directory=frontend_dir, html=True), name="static")

# Redirect root to /static/index.html
@app.get("/")
async def root():
    return RedirectResponse(url="/static/index.html")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

# Cache simples para evitar reprocessamento
metrics_cache = {"data": None, "last_modified": None}

# Pydantic Models
class LoginRequest(BaseModel):
    username: str
    password: str
    
    @validator('username')
    def username_must_not_be_empty(cls, v):
        if not v or not v.strip():
            raise ValueError('Username não pode estar vazio')
        return v.strip()

class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    user: Dict[str, Any]

class UserInfo(BaseModel):
    username: str
    role: str

# Utility Functions
def load_users():
    """Carrega usuários do CSV"""
    try:
        users = []
        with open("data/users.csv", "r", encoding="utf-8") as file:
            reader = csv.DictReader(file)
            for row in reader:
                users.append(row)
        return users
    except FileNotFoundError:
        logger.error("Arquivo users.csv não encontrado")
        return []
    except Exception as e:
        logger.error(f"Erro ao carregar usuários: {e}")
        return []

def get_file_modified_time(file_path):
    """Pega o timestamp de modificação do arquivo"""
    try:
        return os.path.getmtime(file_path)
    except:
        return 0

def load_metrics_optimized(start_date=None, end_date=None, sort_by="date", sort_desc=False, page=1, page_size=25):
    """Carrega métricas do CSV de forma otimizada com paginação"""
    try:
        csv_path = "data/metrics.csv"
        
        if not os.path.exists(csv_path):
            logger.error("Arquivo metrics.csv não encontrado")
            return [], 0
        
        logger.info(f"Carregando dados - Página {page}, Tamanho {page_size}")
        
        start_dt = None
        end_dt = None
        
        if start_date:
            try:
                start_dt = datetime.strptime(start_date, '%Y-%m-%d')
            except ValueError:
                logger.warning(f"Data inicial inválida: {start_date}")
        
        if end_date:
            try:
                end_dt = datetime.strptime(end_date, '%Y-%m-%d')
            except ValueError:
                logger.warning(f"Data final inválida: {end_date}")
        
        all_metrics = []
        processed_rows = 0
        
        def normalize_num(val):
            if not val or not isinstance(val, str):
                return float(val or 0)
            val = val.strip()
            if ',' in val:
                if '.' in val and val.rfind('.') < val.rfind(','):
                    val = val.replace('.', '').replace(',', '.')
                else:
                    val = val.replace(',', '.')
            return float(val)
        
        with open(csv_path, "r", encoding="utf-8") as file:
            reader = csv.DictReader(file)
            
            for row in reader:
                processed_rows += 1
                
                if processed_rows % 100000 == 0:
                    logger.info(f"Processadas {processed_rows} linhas, filtradas {len(all_metrics)}")
                
                try:
                    row_date = datetime.strptime(row['date'], '%Y-%m-%d')
                    
                    if start_dt and row_date < start_dt:
                        continue
                    if end_dt and row_date > end_dt:
                        continue
                    
                    row['cost_micros'] = normalize_num(row.get('cost_micros', '0'))
                    row['clicks'] = normalize_num(row.get('clicks', '0'))
                    row['conversions'] = normalize_num(row.get('conversions', '0'))
                    row['impressions'] = normalize_num(row.get('impressions', '0'))
                    row['interactions'] = normalize_num(row.get('interactions', '0'))
                    row['date'] = row_date
                    
                    all_metrics.append(row)
                        
                except (ValueError, KeyError) as e:
                    continue
        
        total_filtered = len(all_metrics)
        logger.info(f"Carregamento concluído: {processed_rows} processadas, {total_filtered} filtradas")
        
        all_metrics = sort_data(all_metrics, sort_by, sort_desc)
        
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        paginated_data = all_metrics[start_idx:end_idx]
        
        logger.info(f"Retornando página {page}: registros {start_idx} a {end_idx} de {total_filtered}")
        
        return paginated_data, total_filtered
        
    except FileNotFoundError:
        logger.error("Arquivo metrics.csv não encontrado")
        return [], 0
    except Exception as e:
        logger.error(f"Erro ao carregar métricas: {e}")
        return [], 0

def authenticate_user(username: str, password: str):
    """Autentica usuário"""
    users = load_users()
    for user in users:
        if user['username'] == username and user['password'] == password:
            return user
    return None

def create_access_token(data: dict):
    """Cria token JWT"""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Obtém usuário atual do token"""
    token = credentials.credentials
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token inválido",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    users = load_users()
    user = next((u for u in users if u['username'] == username), None)
    if user is None:
        raise credentials_exception
    
    return user

def sort_data(data, sort_by="date", sort_desc=False):
    """Ordena os dados"""
    try:
        if sort_by == 'date':
            def date_key(x):
                val = x.get('date')
                if isinstance(val, datetime):
                    return val
                try:
                    return datetime.strptime(val, '%Y-%m-%d')
                except Exception:
                    return datetime.min
            data.sort(key=date_key, reverse=sort_desc)
        elif sort_by in ['cost_micros', 'clicks', 'conversions', 'impressions', 'interactions']:
            def num_key(x):
                try:
                    return float(x.get(sort_by, 0))
                except Exception:
                    return 0.0
            data.sort(key=num_key, reverse=sort_desc)
        elif sort_by in ['account_id', 'campaign_id']:
            data.sort(key=lambda x: str(x.get(sort_by, '')), reverse=sort_desc)
        return data
    except Exception as e:
        logger.warning(f"Erro ao ordenar dados: {e}")
        return data

# Routes
@app.post("/login", response_model=LoginResponse)
async def login(login_request: LoginRequest):
    """Endpoint de autenticação"""
    logger.info(f"Tentativa de login para usuário: {login_request.username}")
    
    user = authenticate_user(login_request.username, login_request.password)
    if not user:
        logger.warning(f"Login falhou para usuário: {login_request.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais inválidas"
        )
    
    access_token = create_access_token(data={"sub": user['username']})
    logger.info(f"Login bem-sucedido para usuário: {login_request.username}")
    
    return LoginResponse(
        access_token=access_token,
        token_type="bearer",
        user={"username": user['username'], "role": user['role']}
    )

@app.get("/me", response_model=UserInfo)
async def get_user_info(current_user: dict = Depends(get_current_user)):
    """Retorna informações do usuário atual"""
    return UserInfo(username=current_user['username'], role=current_user['role'])

@app.get("/columns")
async def get_available_columns(current_user: dict = Depends(get_current_user)):
    """Retorna colunas disponíveis baseado no role do usuário"""
    base_columns = [
        {"key": "account_id", "label": "Account ID"},
        {"key": "campaign_id", "label": "Campaign ID"},
        {"key": "clicks", "label": "Clicks"},
        {"key": "conversions", "label": "Conversions"},
        {"key": "impressions", "label": "Impressions"},
        {"key": "interactions", "label": "Interactions"},
        {"key": "date", "label": "Date"}
    ]
    
    if current_user['role'] == 'admin':
        base_columns.insert(2, {"key": "cost_micros", "label": "Cost (Micros)"})
    
    return {"columns": base_columns}

@app.get("/data")
async def get_metrics_data(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    sort_by: str = "date",
    sort_desc: bool = False,
    page: int = 1,
    page_size: int = 25,
    current_user: dict = Depends(get_current_user)
):
    """Retorna dados de métricas com filtros e paginação"""
    try:
        page_size = min(page_size, MAX_RECORDS_PER_REQUEST)
        page = max(1, page)
        
        logger.info(f"Buscando dados para {current_user['username']} - Página {page}, Tamanho {page_size}")
        
        data, total = load_metrics_optimized(start_date, end_date, sort_by, sort_desc, page, page_size)
        
        if not data:
            logger.warning("Nenhum dado encontrado")
            return {
                "data": [], 
                "total": 0, 
                "page": page,
                "page_size": page_size,
                "total_pages": 0,
                "message": "Nenhum dado encontrado"
            }
        
        # Função para formatar números no padrão brasileiro
        def format_br(value):
            if value == 0:
                return "0,00"
            str_value = f"{value:,.2f}"
            str_value = str_value.replace(',', 'TEMP')
            str_value = str_value.replace('.', ',')
            str_value = str_value.replace('TEMP', '.')
            return str_value
        
        response_data = []
        for row in data:
            item = {}
            
            item['account_id'] = str(row.get('account_id', ''))
            item['campaign_id'] = str(row.get('campaign_id', ''))
            item['clicks'] = format_br(row.get('clicks', 0))
            item['conversions'] = format_br(row.get('conversions', 0))
            item['impressions'] = format_br(row.get('impressions', 0))
            item['interactions'] = format_br(row.get('interactions', 0))
            item['date'] = row.get('date', datetime.now()).strftime('%Y-%m-%d')
            
            if current_user['role'] == 'admin':
                item['cost_micros'] = format_br(row.get('cost_micros', 0))
            
            response_data.append(item)
        
        total_pages = (total + page_size - 1) // page_size
        
        logger.info(f"Retornando {len(response_data)} registros (página {page} de {total_pages})")
        
        return {
            "data": response_data, 
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
            "showing": len(response_data)
        }
        
    except Exception as e:
        logger.error(f"Erro ao buscar dados: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erro interno do servidor: {str(e)}"
        )

@app.get("/stats")
async def get_basic_stats(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """Retorna estatísticas básicas dos dados filtrados"""
    try:
        logger.info(f"Calculando estatísticas para {current_user['username']}")
        
        sample_data, total = load_metrics_optimized(start_date, end_date, "date", False, 1, 5000)
        
        if not sample_data:
            return {
                "total_records": 0,
                "total_clicks": "0",
                "total_conversions": "0", 
                "total_impressions": "0"
            }
        
        total_clicks = sum(row.get('clicks', 0) for row in sample_data)
        total_conversions = sum(row.get('conversions', 0) for row in sample_data)
        total_impressions = sum(row.get('impressions', 0) for row in sample_data)
        
        return {
            "total_records": total,
            "total_clicks": f"{total_clicks:,.0f}",
            "total_conversions": f"{total_conversions:,.0f}",
            "total_impressions": f"{total_impressions:,.0f}",
            "note": f"Calculado com amostra de {len(sample_data)} registros" if total > len(sample_data) else None
        }
        
    except Exception as e:
        logger.error(f"Erro ao calcular estatísticas: {e}")
        return {
            "total_records": 0,
            "total_clicks": "0",
            "total_conversions": "0",
            "total_impressions": "0",
            "error": str(e)
        }

@app.get("/health")
async def health_check():
    """Endpoint de health check"""
    csv_exists = os.path.exists("data/metrics.csv")
    csv_size = os.path.getsize("data/metrics.csv") if csv_exists else 0
    
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow(),
        "csv_exists": csv_exists,
        "csv_size_mb": round(csv_size / (1024*1024), 2),
        "max_records_per_request": MAX_RECORDS_PER_REQUEST
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)