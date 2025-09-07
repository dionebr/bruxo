# 🧙 Bruxo - Plataforma de Red Team com IA

Bruxo é uma plataforma de segurança ofensiva de ponta que vai além de um simples scanner de vulnerabilidades. Ele integra um motor de varredura rápido, um painel de C2 (Comando e Controle) interativo e um simulador de cenários de ataque alimentado por IA para fornecer uma visão completa e acionável do postura de segurança de um alvo.

## ✨ Principais Funcionalidades

- **Scanner de Diretórios Rápido**: Utiliza `fasthttp` e concorrência para escanear diretórios e arquivos em alta velocidade.
- **Análise de Vulnerabilidades**: Detecta automaticamente vulnerabilidades comuns como repositórios Git expostos, arquivos de configuração sensíveis e cabeçalhos de segurança ausentes.
- **Painel de C2 Integrado**: Um painel de comando e controle completo, acessível diretamente pelo relatório HTML, que permite:
    - Visualizar agentes conectados em tempo real.
    - Enviar comandos para agentes individuais através de um terminal web.
    - Fazer upload e download de arquivos entre o servidor C2 e o agente.
- **Agente C2 Multiplataforma**: Um agente leve em Go que inclui funcionalidades de persistência para Linux (systemd) e Windows (Registro).
- **Simulador de Cenários de Ataque com IA**: Utiliza a API da Groq (com o modelo Llama 3 70B) para analisar as vulnerabilidades encontradas e gerar dinamicamente cenários de ataque realistas, incluindo objetivos, passos, tempo estimado e probabilidade de sucesso.
- **Playbooks Interativos**: Os cenários de ataque gerados são interativos. Clicar em um passo do cenário preenche automaticamente o comando correspondente no terminal do agente C2 apropriado.
- **Relatório Tático Interativo**: Gera um relatório HTML único que serve como um dashboard tático, com heatmap de vulnerabilidades, caminhos de ataque e o painel de C2.

## ⚙️ Arquitetura

O Bruxo é composto por três componentes principais:

1.  **Servidor Bruxo (`bruxo`)**: O núcleo da plataforma. Ele executa o scan, serve o relatório HTML e opera o servidor C2 na porta `:8080`.
2.  **Agente (`agent`)**: Um implante leve que é executado no alvo. Ele se conecta ao servidor C2 para receber tarefas (comandos) e enviar resultados.
3.  **Painel de Controle (Relatório HTML)**: A interface do usuário, que é um arquivo HTML dinâmico. Ele exibe os resultados do scan e fornece a interface interativa para o C2 e os cenários de ataque.

## 🚀 Requisitos e Instalação

### Dependências

- **Go**: Versão 1.18 ou superior.
- **Git**: Para controle de versão.

### Configuração do Ambiente

1.  **Clone o Repositório**:
    ```bash
    git clone https://github.com/dionebr/bruxo.git
    cd bruxo
    ```

2.  **Instale as Dependências do Servidor**:
    ```bash
    go mod tidy
    ```

3.  **Instale as Dependências do Agente**:
    ```bash
    cd agent
    go mod tidy
    cd ..
    ```

4.  **Configurar a Chave da API da Groq**:
    Para usar o Simulador de Cenários com IA, você precisa de uma chave de API da Groq. Exporte-a como uma variável de ambiente:
    ```bash
    export GROQ_API_KEY="sua_chave_api_aqui"
    ```

## 🛠️ Compilação

### Compilando o Servidor Bruxo

No diretório raiz do projeto, execute:
```bash
go build -o bruxo bruxo.go
```

### Compilando o Agente

Para compilar o agente para diferentes sistemas operacionais:

- **Para Linux:**
  ```bash
  cd agent
  GOOS=linux GOARCH=amd64 go build -o agent_linux
  cd ..
  ```
- **Para Windows:**
  ```bash
  cd agent
  GOOS=windows GOARCH=amd64 go build -o agent_windows.exe
  cd ..
  ```

## 📖 Guia de Uso

1.  **Execute o Servidor Bruxo**:
    Inicie um scan em um alvo. O servidor C2 iniciará automaticamente na porta `:8080`.
    ```bash
    ./bruxo -u http://alvo.com -w /caminho/para/wordlist.txt -o report.html --attack-flow
    ```

2.  **Implante e Execute o Agente**:
    Transfira o agente compilado (ex: `agent_linux`) para a máquina alvo e execute-o.
    ```bash
    chmod +x ./agent_linux
    ./agent_linux
    ```

3.  **Abra o Relatório e Use o C2**:
    - Abra o `report.html` em seu navegador.
    - Role para baixo até a seção "C2 Agents". O novo agente deve aparecer na tabela.
    - Clique no agente para abrir o terminal e comece a enviar comandos (`whoami`, `ls -la`, etc.).
    - Use o comando `persist` para instalar o agente permanentemente no alvo.
    - Use `upload` e `download` para transferir arquivos.

4.  **Use os Playbooks Interativos**:
    - Analise os cenários de ataque gerados pela IA.
    - Clique em um passo de um cenário. O comando correspondente será preenchido no terminal do agente apropriado, pronto para ser executado.
