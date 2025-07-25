#!/usr/bin/env python3
"""
Sistema de Descoberta Massiva de Domínios - Arquitetura de Ultra Alto Throughput
===============================================================================

Implementação ultra-otimizada para máxima concorrência com:
- Pool de conexões dinâmico com até 50 conexões simultâneas
- Processamento assíncrono de até 500 domínios por ciclo
- Zero delays artificiais - throughput I/O bound maximizado
- Otimização de memória e CPU para operação sustentável

Arquitetura de Performance:
- Conexões: Pool dinâmico de até 50 conexões simultâneas
- Batch Size: Até 500 URLs processadas concorrentemente
- Memory Footprint: <100MB otimizado
- Target Throughput: >15000 verificações/minuto

pip install aiohttp aiofiles uvloop
"""

import asyncio
import aiohttp
import aiofiles
import json
import string
import time
import logging
import sys
import signal
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Set, Deque
from dataclasses import dataclass
from collections import deque
import os

# Otimização do event loop com uvloop (significativamente mais rápido que o asyncio padrão)
try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    USING_UVLOOP = True
except ImportError:
    USING_UVLOOP = False

# Configuração de logging minimalista para máxima performance
logging.basicConfig(
    level=logging.ERROR,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler("scanner_errors.log"), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# UTF-8 Windows compatibility
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

@dataclass
class HighPerformanceConfig:
    """Configuração ultra-otimizada para máximo throughput"""
    
    # Arquitetura de Concorrência Ultra-Otimizada
    max_concurrent_connections: int = 50      # Pool de conexões simultâneas (aumentado)
    batch_processing_size: int = 500          # URLs processadas por ciclo (aumentado)
    connection_pool_limit: int = 100          # Pool de conexões HTTP (aumentado)
    
    # Timeouts Ultra-Agressivos para Velocidade Máxima
    connection_timeout: float = 1.5           # Conexão TCP (reduzido)
    read_timeout: float = 2.0                 # Leitura de response (reduzido)
    total_timeout: float = 3.5                # Timeout total (reduzido)
    
    # Estratégia de Retry Minimalista
    max_retries: int = 0                      # Zero retries para máxima velocidade
    
    # Configurações de Output
    output_file: str = "active_domains.txt"
    checkpoint_file: str = "checkpoint.json"
    
    # TLDs para verificação
    target_tlds: List[str] = None
    
    # Configurações de Buffer
    write_buffer_size: int = 100              # Tamanho do buffer de escrita (aumentado)
    
    # Configurações de Feedback
    stats_update_interval: float = 2.0        # Intervalo de atualização de estatísticas
    checkpoint_interval: float = 30.0         # Intervalo de checkpoint
    
    def __post_init__(self):
        if self.target_tlds is None:
            self.target_tlds = ['.com', '.org', '.net', '.io', '.app']

@dataclass
class SystemMetrics:
    """Métricas de sistema em tempo real"""
    current_payload: str = "a"
    total_processed: int = 0
    domains_found: int = 0
    start_time: float = 0
    requests_per_second: float = 0
    active_connections: int = 0
    last_update_time: float = 0
    last_processed_count: int = 0

class HighSpeedPayloadGenerator:
    """Gerador de payload com iteração sequencial otimizada"""
    
    def __init__(self, start: str = "a"):
        self.current = start
        self.alphabet = string.ascii_lowercase
        self.iteration_count = 0
        
        # Cache de payloads pré-calculados para reduzir overhead
        self._payload_cache: Deque[str] = deque(maxlen=1000)
        self._prefill_cache(100)  # Pré-calcula 100 payloads
    
    def _prefill_cache(self, count: int):
        """Pré-calcula payloads para reduzir overhead durante execução"""
        current = self.current
        for _ in range(count):
            self._payload_cache.append(current)
            current = self._increment(current)
    
    def _increment(self, s: str) -> str:
        """Algoritmo de incremento otimizado"""
        if not s:
            return "a"
        
        chars = list(s)
        i = len(chars) - 1
        
        while i >= 0:
            if chars[i] == 'z':
                chars[i] = 'a'
                i -= 1
            else:
                chars[i] = chr(ord(chars[i]) + 1)
                return ''.join(chars)
        
        # Overflow: expande para próximo tamanho
        return 'a' * (len(s) + 1)
    
    def get_next_payload(self) -> str:
        """Retorna próximo payload com cache otimizado"""
        if not self._payload_cache:
            self._prefill_cache(100)
        
        current_payload = self._payload_cache.popleft()
        self.current = self._increment(current_payload)
        self._payload_cache.append(self.current)
        self.iteration_count += 1
        
        return current_payload
    
    def get_batch(self, size: int) -> List[str]:
        """Retorna batch sequencial de payloads otimizado"""
        if len(self._payload_cache) < size:
            self._prefill_cache(size * 2)
        
        batch = []
        for _ in range(size):
            batch.append(self.get_next_payload())
        
        return batch
    
    def get_current_payload(self) -> str:
        """Retorna payload atual sem modificar estado"""
        return self.current

class HighThroughputNetworkEngine:
    """Engine de rede ultra-otimizado para máximo throughput"""
    
    def __init__(self, config: HighPerformanceConfig):
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Semáforo dinâmico para controle de conexões
        self.semaphore = asyncio.Semaphore(config.max_concurrent_connections)
        
        # Contadores atômicos para métricas
        self.active_connections = 0
        
        # Cache de resultados para domínios já verificados
        self.result_cache = {}
        self.cache_hits = 0
    
    async def __aenter__(self):
        await self._initialize_session()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self._cleanup()
    
    async def _initialize_session(self):
        """Inicialização ultra-otimizada para máxima performance"""
        
        # Connector TCP ultra-otimizado
        connector = aiohttp.TCPConnector(
            limit=self.config.connection_pool_limit,
            limit_per_host=self.config.max_concurrent_connections,
            ttl_dns_cache=600,                    # Cache DNS estendido
            use_dns_cache=True,
            keepalive_timeout=120,                # Keep-alive estendido
            enable_cleanup_closed=True,
            force_close=False,                    # Evita fechamento forçado
            ssl=False                             # Desativa verificação SSL para velocidade
        )
        
        # Timeout configuration ultra-agressiva
        timeout = aiohttp.ClientTimeout(
            total=self.config.total_timeout,
            connect=self.config.connection_timeout,
            sock_read=self.config.read_timeout
        )
        
        # Headers minimalistas para performance
        headers = {
            'User-Agent': 'Mozilla/5.0 High-Speed Scanner',
            'Accept': '*/*',
            'Connection': 'keep-alive'
        }
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=headers,
            raise_for_status=False
        )
    
    async def _cleanup(self):
        """Cleanup otimizado"""
        if self.session and not self.session.closed:
            await self.session.close()
    
    async def verify_domain_batch(self, urls: List[str]) -> List[Tuple[str, bool, int]]:
        """Processamento de batch ultra-otimizado"""
        
        # Cria tasks para todas as URLs simultaneamente
        tasks = []
        for url in urls:
            # Verifica cache primeiro
            if url in self.result_cache:
                self.cache_hits += 1
                continue
            
            tasks.append(self._verify_single_domain(url))
        
        # Executa todas as verificações concorrentemente
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Processa resultados
        valid_results = []
        for result in results:
            if isinstance(result, tuple):
                url, is_active, status = result
                # Adiciona ao cache para futuras referências
                self.result_cache[url] = (is_active, status)
                valid_results.append(result)
            else:
                # Exception occurred
                valid_results.append(("", False, 0))
        
        return valid_results
    
    async def _verify_single_domain(self, url: str) -> Tuple[str, bool, int]:
        """Verificação individual ultra-otimizada"""
        
        async with self.semaphore:
            self.active_connections += 1
            
            try:
                async with self.session.get(url, allow_redirects=False) as response:
                    status = response.status
                    
                    # Critérios de domínio ativo otimizados
                    is_active = status in {200, 201, 301, 302, 307, 308, 403, 404}
                    
                    return url, is_active, status
            
            except asyncio.TimeoutError:
                return url, False, 0
            except Exception as e:
                return url, False, 0
            
            finally:
                self.active_connections -= 1

class HighSpeedPersistenceManager:
    """Gerenciador de persistência ultra-otimizado"""
    
    def __init__(self, config: HighPerformanceConfig):
        self.config = config
        self.active_domains_file = Path(config.output_file)
        self.checkpoint_file = Path(config.checkpoint_file)
        
        # Buffer para escritas em batch
        self.write_buffer = []
        self.buffer_size = config.write_buffer_size
        
        # Lock para operações de I/O
        self.io_lock = asyncio.Lock()
        
        # Conjunto para rastreamento de domínios já salvos
        self.saved_domains = set()
        self._load_existing_domains()
    
    def _load_existing_domains(self):
        """Carrega domínios já salvos para evitar duplicatas"""
        try:
            if self.active_domains_file.exists():
                with open(self.active_domains_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        domain = line.strip()
                        if domain:
                            self.saved_domains.add(domain)
        except Exception:
            pass
    
    async def save_active_domain(self, url: str):
        """Salva domínio ativo com buffering ultra-otimizado"""
        # Evita duplicatas
        if url in self.saved_domains:
            return
        
        self.saved_domains.add(url)
        self.write_buffer.append(url)
        
        # Flush buffer quando atingir tamanho limite
        if len(self.write_buffer) >= self.buffer_size:
            await self._flush_buffer()
    
    async def _flush_buffer(self):
        """Flush buffer para disco de forma ultra-eficiente"""
        if not self.write_buffer:
            return
        
        # Usa lock para evitar race conditions
        async with self.io_lock:
            try:
                buffer_to_write = self.write_buffer.copy()
                self.write_buffer.clear()
                
                async with aiofiles.open(self.active_domains_file, 'a', encoding='utf-8') as f:
                    await f.write('\n'.join(buffer_to_write) + '\n')
            except Exception as e:
                logger.error(f"Erro ao salvar domínios: {e}")
                # Recupera buffer em caso de falha
                self.write_buffer.extend(buffer_to_write)
    
    async def save_checkpoint(self, metrics: SystemMetrics):
        """Checkpoint ultra-rápido para recovery"""
        try:
            checkpoint_data = {
                'current_payload': metrics.current_payload,
                'total_processed': metrics.total_processed,
                'domains_found': metrics.domains_found,
                'timestamp': time.time()
            }
            
            # Usa lock para evitar race conditions
            async with self.io_lock:
                async with aiofiles.open(self.checkpoint_file, 'w', encoding='utf-8') as f:
                    await f.write(json.dumps(checkpoint_data, indent=2))
        except Exception:
            pass  # Silencia erros de checkpoint para não impactar performance
    
    async def finalize(self):
        """Finalização com flush de buffer pendente"""
        await self._flush_buffer()

class HighPerformanceDomainScanner:
    """Scanner principal com arquitetura de ultra-alta performance"""
    
    def __init__(self, config: HighPerformanceConfig):
        self.config = config
        self.payload_generator = HighSpeedPayloadGenerator()
        self.persistence = HighSpeedPersistenceManager(config)
        self.metrics = SystemMetrics()
        
        self.running = False
        self.shutdown_event = asyncio.Event()
        
        # Estatísticas para monitoramento
        self.metrics.last_update_time = time.time()
        self.metrics.last_processed_count = 0
        
        # Controle de feedback
        self.last_feedback_time = time.time()
        self.feedback_interval = 5.0  # segundos
        
        self._setup_signal_handlers()
    
    def _setup_signal_handlers(self):
        """Signal handlers para shutdown gracioso"""
        def signal_handler(signum, frame):
            print(f"\n🛑 Shutdown signal recebido...")
            self.shutdown_event.set()
        
        signal.signal(signal.SIGINT, signal_handler)
        if hasattr(signal, 'SIGTERM'):
            signal.signal(signal.SIGTERM, signal_handler)
    
    async def run(self):
        """Execução principal com máxima performance"""
        
        print(f"🚀 Iniciando Scanner de Ultra-Alta Performance")
        if USING_UVLOOP:
            print("⚡ Usando uvloop para performance máxima")
        print("=" * 60)
        
        self.running = True
        self.metrics.start_time = time.time()
        
        async with HighThroughputNetworkEngine(self.config) as network:
            # Tasks principais executando concorrentemente
            tasks = [
                asyncio.create_task(self._scanning_loop(network)),
                asyncio.create_task(self._stats_monitor()),
                asyncio.create_task(self._checkpoint_monitor())
            ]
            
            # Aguarda shutdown ou completion
            done, pending = await asyncio.wait(
                tasks + [asyncio.create_task(self.shutdown_event.wait())],
                return_when=asyncio.FIRST_COMPLETED
            )
            
            # Cancela tasks pendentes
            for task in pending:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        
        await self._finalize()
    
    async def _scanning_loop(self, network: HighThroughputNetworkEngine):
        """Loop principal ultra-otimizado"""
        
        batch_counter = 0
        
        print("🚀 Iniciando loop de descoberta assíncrona...")
        
        while self.running and not self.shutdown_event.is_set():
            try:
                # Gera batch de payloads para processamento paralelo
                payloads = self.payload_generator.get_batch(self.config.batch_processing_size)
                
                # Construção de URLs para verificação paralela
                urls = []
                for payload in payloads:
                    for tld in self.config.target_tlds:
                        urls.append(f"https://{payload}{tld}")
                
                # Execução concorrente ultra-otimizada
                results = await network.verify_domain_batch(urls)
                
                # Processamento de resultados otimizado
                active_count = 0
                for url, is_active, status in results:
                    if is_active and status in {200, 301, 302}:
                        active_count += 1
                        await self.persistence.save_active_domain(url)
                
                # Atualização de métricas
                self.metrics.current_payload = self.payload_generator.get_current_payload()
                self.metrics.total_processed += len(urls)
                self.metrics.domains_found += active_count
                
                batch_counter += 1
                
                # Feedback de progressão otimizado (apenas a cada intervalo)
                current_time = time.time()
                if current_time - self.last_feedback_time >= self.feedback_interval:
                    self.last_feedback_time = current_time
                    
                    # Feedback minimalista para não impactar performance
                    print(f"\n📊 BATCH #{batch_counter} | Payload: {self.metrics.current_payload} | Ativos: +{active_count} | Total: {self.metrics.domains_found}")
                
            except Exception as e:
                logger.error(f"Falha no scanning loop: {e}")
                # Sistema continua operação para próximo payload
    
    async def _stats_monitor(self):
        """Monitor de estatísticas otimizado"""
        
        while self.running and not self.shutdown_event.is_set():
            try:
                await asyncio.sleep(self.config.stats_update_interval)
                
                current_time = time.time()
                elapsed = current_time - self.metrics.last_update_time
                
                processed_delta = self.metrics.total_processed - self.metrics.last_processed_count
                self.metrics.requests_per_second = processed_delta / elapsed if elapsed > 0 else 0
                
                total_elapsed = current_time - self.metrics.start_time
                
                # Display estatísticas principais
                stats_line = (
                    f"\n📊 MONITORAMENTO DE PERFORMANCE\n"
                    f"{'='*60}\n"
                    f"🔍 Payload: {self.metrics.current_payload:>15} | "
                    f"📈 Processado: {self.metrics.total_processed:>10,} | "
                    f"🌐 Ativos: {self.metrics.domains_found:>10,}\n" 
                    f"⚡ Velocidade: {self.metrics.requests_per_second:>10.1f}/s | "
                    f"⏱️ Runtime: {total_elapsed/60:>10.1f} min | "
                    f"🔗 Conexões: {self.metrics.active_connections:>5}/{self.config.max_concurrent_connections}\n"
                    f"{'='*60}"
                )
                
                print(stats_line)
                
                self.metrics.last_update_time = current_time
                self.metrics.last_processed_count = self.metrics.total_processed
                
            except Exception as e:
                logger.error(f"Erro no stats monitor: {e}")
                await asyncio.sleep(1)
    
    async def _checkpoint_monitor(self):
        """Monitor de checkpoint otimizado"""
        
        while self.running and not self.shutdown_event.is_set():
            try:
                await asyncio.sleep(self.config.checkpoint_interval)
                await self.persistence.save_checkpoint(self.metrics)
            except Exception:
                pass  # Silencia erros para não impactar performance
    
    async def _finalize(self):
        """Finalização do sistema"""
        
        print("\n\n🏁 Finalizando Scanner...")
        self.running = False
        
        # Salva dados pendentes
        await self.persistence.finalize()
        await self.persistence.save_checkpoint(self.metrics)
        
        # Estatísticas finais
        total_time = time.time() - self.metrics.start_time
        avg_speed = self.metrics.total_processed / total_time if total_time > 0 else 0
        
        print(f"""
📊 RELATÓRIO FINAL DE PERFORMANCE
{'-' * 50}
Total Processado: {self.metrics.total_processed:,} URLs
Domínios Ativos: {self.metrics.domains_found:,}
Velocidade Média: {avg_speed:.0f} req/s
Tempo Total: {total_time/60:.2f} minutos
Último Payload: {self.metrics.current_payload}
Taxa de Sucesso: {(self.metrics.domains_found/self.metrics.total_processed*100):.4f}%
""")

async def main():
    """Função principal ultra-otimizada"""
    
    # Configuração de ultra-alta performance
    config = HighPerformanceConfig(
        max_concurrent_connections=50,        # 50 conexões simultâneas (aumentado)
        batch_processing_size=500,            # 500 URLs por batch (aumentado)
        connection_pool_limit=100,            # Pool de 100 conexões (aumentado)
        connection_timeout=1.5,               # Timeouts ultra-agressivos
        read_timeout=2.0,
        total_timeout=3.5,
        max_retries=0,                        # Zero retries para velocidade máxima
        write_buffer_size=100,                # Buffer de escrita maior
        stats_update_interval=2.0,            # Atualização de estatísticas a cada 2s
        checkpoint_interval=30.0              # Checkpoint a cada 30s
    )
    
    # Ajusta configurações com base em recursos do sistema
    try:
        import psutil
        # Ajusta conexões com base em CPU cores
        cpu_count = os.cpu_count() or 4
        mem_info = psutil.virtual_memory()
        
        # Ajusta conexões com base em CPU e memória
        if cpu_count >= 8 and mem_info.available > 4 * 1024 * 1024 * 1024:  # >4GB livre
            config.max_concurrent_connections = 100
            config.batch_processing_size = 1000
        elif cpu_count >= 4 and mem_info.available > 2 * 1024 * 1024 * 1024:  # >2GB livre
            config.max_concurrent_connections = 75
            config.batch_processing_size = 750
        
        print(f"🔧 Configuração auto-ajustada: {config.max_concurrent_connections} conexões, batch de {config.batch_processing_size}")
    except ImportError:
        # psutil não disponível, usa configuração padrão
        pass
    
    # Inicializa e executa scanner
    scanner = HighPerformanceDomainScanner(config)
    
    try:
        await scanner.run()
    except KeyboardInterrupt:
        print("\n⚡ Execução interrompida pelo usuário")
    except Exception as e:
        print(f"\n❌ Erro crítico: {e}")
        logger.exception("Erro crítico")

if __name__ == "__main__":
    # Execução com configuração de ultra-alta performance
    asyncio.run(main(), debug=False)