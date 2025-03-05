from io import BytesIO
from __init__ import criar_banco, criar_usuario, login
import requests
from PIL import Image

#from __init__ import criar_banco, criar_usuario

if __name__ == '__main__':
    # conn = sqlite3.connect("usuarios.db")
    conexao = criar_banco()

    email_usuario = input("qual o email do usuário?")
    senha_usuario = input("qual a senha?")
    usar_otp = True if input("usar 2fa?").lower()[0] == "s" else False

    novo_usuario = criar_usuario(conexao, email_usuario, senha_usuario, usar_otp)

    if novo_usuario is None:
        print(f"email já cadastrado")
    else:
        segredo_otp, uri_otp, codigos_reserva = novo_usuario
        if segredo_otp:
            print("usuario criado com 2fa")
            print(f"segredo OTP: {segredo_otp}")
            print(f"URI OTP: {uri_otp}")
            print(f"codigos reserva:")
            for codigo in codigos_reserva:
                print(f"- {codigo}")
            url = f"https://quickchart.io/chart?cht=qr&chs=300x300&chl={uri_otp}"
            r = requests.get(url)
            if r.status_code == requests.codes.ok:
                print("QR-Code de conguracao salvo em 'qrcode.png'")
                Image.open(BytesIO(r.content)).save("qrcode.png")
            else:
                print("Erro ao gerar e salvar o QR-Code de configuracao")
        else:
            print("usuario criado sem 2fa")

    senha_usuario = input("digite a senha para verificação:")
    if usar_otp:
        codigo_otp = input("digite o codigo OTP:")
        autenticado = login(conexao, email_usuario, senha_usuario, codigo_otp)
    else:
        autenticado = login(conexao, email_usuario, senha_usuario)

    if autenticado:
        print("logado com sucesso")
    else:
        print("falha na autenticacao")

    

