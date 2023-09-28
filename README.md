#Ransomware-hooker 🛡️
*Nossa solução foi desenvolvida em C++, especializados em sistemas windows. Visamos alta performance com baixo consumo de recursos.*
*Nosso EDR trabalha com o hooking de APIs, mais precisamente das funções das APIs Create File, CryptoApi e da Move File.*
*Possuímos automatizção das respostas quando identificado um processo que esteja fazendo uso malicioso dessas APIs* e possuímos um injector que faz o monitoramento dos processos em execução em tempo real, além disso ele identifica os processos que subiram junto com o sistema e os separa dos novos processos.* 
*Fazemos o uso da biblioteca EasyHook que nos permite o monitoramento dessas funções, ajudando na comunicação do nosso código com as APIs.*

#Manual de instalação da nossa ferramenta 📜
1. Acesse o repositorio no GitHub 
2. Clique em ```Code``` > ```Download ZIP```
3. Extraia o arquivo instalado que está zipado
4. Extraia o arquivo ```Eagle - Antiransomware.zip``` (Este arquivo é o instalador, os outros são do código da nossa ferramenta)
5. Escolha um dentre os dois instaladores que tem para fazer a instalação do programa
6. Clique duas vezes para abrir o instalador e começar a instalação da ferramenta
7. Caso apareça a seguinte mensagem do windows "O Windows protegeu o computador", clique em ```mais informações``` > ```Executar assim mesmo```
8. Clique em ```Avançar >``` > faça as alterações de caminho ou de baixar para todos os usuários da máquina caso precise, se não apenas deixe o padrão e clique em ```Avançar >``` > ```Avançar >``` > clique em ```Sim``` no pop-up de segurança do windows e aguarde a instalação da ferramenta. Após instalado, só clicar em ```Fechar```.

#Manual de execução da nossa ferramenta 🤺
1. Abra a ferramenta na área de trabalho
2. Clique no botão ```Ligar``` para iniciar a ferramenta
3. Uma caixa com a mensagem ```Iniciado!``` será exibida, feche-a e pronto, a ferramenta está executada! 
