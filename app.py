from flask import Flask, jsonify
from flask_restful import Api
from flask_jwt_extended import JWTManager

from blacklist import BLACKLIST
from resources.hotel import Hoteis, Hotel
from resources.site import Sites, Site
from resources.usuario import User, UserRegister, UserLogin, UserLogout, UserConfirm

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///banco.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'DontSeeThis'
app.config['JWT_BLACKLIST_ENABLED'] = True
api = Api(app)
jwt = JWTManager(app)

@app.before_first_request
def cria_banco():
    banco.create_all()

@jwt.token_in_blacklist_loader
def verifirica_blacklist(token):
    return token['jti'] in BLACKLIST

@jwt.revoked_token_loader
def token_de_acesso_invalidado():
    return jsonify({'message': 'You have been logged out.'}), 401

api.add_resource(Hoteis, '/hoteis')
api.add_resource(Hotel, '/hoteis/<string:hotel_id>')
api.add_resource(User, '/usuarios/<int:user_id>')
api.add_resource(UserRegister, '/cadastro')
api.add_resource(UserLogin, '/login')
api.add_resource(UserLogout, '/logout')
api.add_resource(Sites, '/sites')
api.add_resource(Site, '/sites/<string:url>')
api.add_resource(UserConfirm, '/confirmacao/<int:user_id>')

'''
def send_simple_message():
    return requests.post(
        "https://api.mailgun.net/v3/sandbox1e650173f44e4525abb38b4c4fb0d899.mailgun.org/messages",
        auth=("api", "bf5bfe585fb96032e6590b73e11f1c95-e438c741-03b1c9bc"),
        data={"from": "Mailgun Sandbox <postmaster@sandbox1e650173f44e4525abb38b4c4fb0d899.mailgun.org>",
              "to": "Leonardo Balduino da Silva <leonardobalduino@hotmail.com>",
              "subject": "Hello Leonardo Balduino da Silva",
              "text": "Congratulations Leonardo Balduino da Silva, you just sent an email with Mailgun!  You are truly awesome!"})
'''

if __name__ == '__main__':
    from sql_alchemy import banco
    banco.init_app(app)
    app.run(debug=True)