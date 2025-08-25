#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe, UserSchema, RecipeSchema

class Signup(Resource):
    def post(self):
        json = request.get_json()

        if not json.get('username') or not json.get('password'):
            return {"errors": "Username and password required"}, 422

        user = User(username=json.get('username'), image_url=json.get('image_url'),
                    bio=json.get('bio'))
        user.password_hash = json.get('password')
        
        try:
            db.session.add(user)
            db.session.commit()
            session['user_id'] = user.id
        except IntegrityError:
            db.session.rollback()
            return {'errors': ["Username must be unique."]}, 422
        except ValueError as e:
            db.session.rollback()
            return {'errors': [str(e)]}, 422
        return UserSchema().dump(user), 201

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if user_id:
            user = User.query.get(user_id)
            if user:
                return UserSchema().dump(user), 200
        return {'error': 'Unauthorized'}, 401

class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        if not username or not password:
            return {'error': 'Username and password required.'}, 401

        user = User.query.filter_by(username=username).first()
        if user and user.authenticate(password):
            session['user_id'] = user.id
            return UserSchema().dump(user), 200
        else:
            return {'error': 'Invalid username or password.'}, 401

class Logout(Resource):
    def delete(self):
        if session.get('user_id'):
            session.pop('user_id', None)
            return '', 204
        else:
            return {'error': 'Unauthorized'}, 401

class RecipeIndex(Resource):
    def get(self):
        if not session.get('user_id'):
            return {'error': 'Unauthorized'}, 401
        recipes = Recipe.query.all()
        return RecipeSchema(many=True).dump(recipes), 200
    def post(self):
        if not session.get('user_id'):
            return {'error': 'Unauthorized'}, 401

        data = request.get_json()

        title = data.get('title')
        instructions = data.get('instructions')
        minutes = data.get('minutes_to_complete')

        if not title or not instructions:
            return {'errors': 'Title and instructions required'}, 422
        elif len(instructions) < 50:
            return {'errors': 'Instructions must be 50 characters or more'}, 422

        user_id = session.get('user_id')
        recipe = Recipe(
            title=title,
            instructions=instructions,
            minutes_to_complete=minutes,
            user_id=user_id
        )
        try:
            db.session.add(recipe)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return {'errors': [str(e)]}, 422

        return RecipeSchema().dump(recipe), 201

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)