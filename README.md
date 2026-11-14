# Criptografia híbrida com OpenSSL

Checkpoint 1 da Atividade 16 de Segurança de Software. Aplicação em Python com interface de terminal, sem dependências Python externas.

## Executar

Use Python 3 e OpenSSL disponíveis no terminal. Execute na pasta do projeto.

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out privada.pem
openssl pkey -in privada.pem -pubout -out publica.pem

python3 app.py cifrar mensagem.txt publica.pem saida
python3 app.py decifrar saida privada.pem mensagem_restaurada.txt
openssl dgst -sha256 mensagem.txt mensagem_restaurada.txt
```

No Windows, se necessário, substitua `python3` por `py`. Use caminhos de saída novos ao repetir o teste. Os dois hashes devem ser iguais.

A aplicação gera um segredo aleatório de 32 bytes para cada arquivo. O OpenSSL usa esse segredo em Base64 como entrada do PBKDF2 para derivar a chave AES-256-CBC e o IV. O segredo original é cifrado com a chave pública RSA do destinatário usando OAEP com SHA-256. A chave privada correspondente recupera o segredo na decifragem.

O diretório de saída contém `mensagem.enc` e `chave_aes.enc`. O teste local usa chaves de simulação. Mantenha a chave privada fora do repositório. O modo CBC segue o enunciado. A autenticação do remetente é uma etapa separada com assinatura digital.

Os comandos manuais e o teste executado estão em [evidencias.txt](evidencias.txt).
