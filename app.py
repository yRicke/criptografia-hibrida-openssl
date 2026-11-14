"""Cifragem híbrida para o checkpoint de Segurança de Software."""

import argparse
import base64
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile


OPCOES_RSA = (
    "-pkeyopt", "rsa_padding_mode:oaep",
    "-pkeyopt", "rsa_oaep_md:sha256",
    "-pkeyopt", "rsa_mgf1_md:sha256",
)


def openssl(*args, entrada=None):
    subprocess.run(["openssl", *args], input=entrada, check=True)


def aes(origem, destino, segredo, modo):
    # O OpenSSL lê uma linha de senha. Base64 preserva os 32 bytes aleatórios.
    senha = base64.b64encode(segredo) + b"\n"
    openssl(
        "enc", "-aes-256-cbc", modo, "-pbkdf2", "-md", "sha256",
        "-in", origem, "-out", destino, "-pass", "stdin", entrada=senha,
    )


def cifrar(arquivo, publica, pacote):
    segredo = secrets.token_bytes(32)
    with tempfile.TemporaryDirectory() as temporario:
        pasta = Path(temporario)
        chave_cifrada = pasta / "chave_aes.enc"
        mensagem_cifrada = pasta / "mensagem.enc"
        openssl(
            "pkeyutl", "-encrypt", "-pubin", "-inkey", publica,
            "-out", chave_cifrada, *OPCOES_RSA, entrada=segredo,
        )
        aes(arquivo, mensagem_cifrada, segredo, "-e")

        pacote.mkdir()
        try:
            shutil.copyfile(chave_cifrada, pacote / chave_cifrada.name)
            shutil.copyfile(mensagem_cifrada, pacote / mensagem_cifrada.name)
        except OSError:
            shutil.rmtree(pacote)
            raise

    print(f"Arquivo cifrado em {pacote}/mensagem.enc")
    print(f"Chave cifrada em {pacote}/chave_aes.enc")


def decifrar(pacote, privada, destino):
    segredo = subprocess.run(
        [
            "openssl", "pkeyutl", "-decrypt", "-inkey", privada,
            "-in", pacote / "chave_aes.enc", *OPCOES_RSA,
        ],
        stdout=subprocess.PIPE,
        check=True,
    ).stdout
    if len(segredo) != 32:
        raise ValueError("A chave recuperada precisa ter 32 bytes.")

    with tempfile.TemporaryDirectory() as temporario:
        restaurado = Path(temporario) / "restaurado"
        aes(pacote / "mensagem.enc", restaurado, segredo, "-d")
        with restaurado.open("rb") as origem, destino.open("xb") as saida:
            try:
                shutil.copyfileobj(origem, saida)
            except OSError:
                saida.close()
                destino.unlink()
                raise

    print(f"Arquivo restaurado em {destino}")


def main():
    parser = argparse.ArgumentParser(description="Criptografia híbrida com OpenSSL")
    comandos = parser.add_subparsers(dest="acao", required=True)

    cifragem = comandos.add_parser("cifrar", help="Cifra um arquivo para o destinatário")
    cifragem.add_argument("arquivo", type=Path)
    cifragem.add_argument("publica", type=Path)
    cifragem.add_argument("pacote", type=Path, help="Diretório novo para os arquivos cifrados")

    decifragem = comandos.add_parser("decifrar", help="Restaura o arquivo original")
    decifragem.add_argument("pacote", type=Path)
    decifragem.add_argument("privada", type=Path)
    decifragem.add_argument("destino", type=Path, help="Caminho novo para o arquivo restaurado")

    args = parser.parse_args()
    try:
        if args.acao == "cifrar":
            cifrar(args.arquivo, args.publica, args.pacote)
        else:
            decifrar(args.pacote, args.privada, args.destino)
    except (OSError, ValueError, subprocess.CalledProcessError) as erro:
        parser.exit(1, f"Erro: {erro}\n")


if __name__ == "__main__":
    main()
