#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")
        image = data.get("image_url")
        bio = data.get("bio")

        user = User(username=username, image_url=image, bio=bio)
        user.password_hash = password

        try:
            db.session.add(user)
            db.session.commit()

            session["user_id"] = user.id
            return user.to_dict(), 201
        except IntegrityError:
            return {"message": "Sign-up failed, username already exists."}, 422

class CheckSession(Resource):
    def get(self):
        if session['user_id']:
            user = User.query.filter(User.id == session['user_id']).first()
            return user.to_dict(), 200
        else:
            return {"message": "Unauthorized access."}, 401

class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")
        user = User.query.filter(username == User.username).first()
        if user and user.authenticate(password):
            session['user_id'] = user.id
            return user.to_dict()
        else:
            return {"message": "Incorrect username or password."}, 401

class Logout(Resource):
    def delete(self):
        if session['user_id']:
            session['user_id'] = None
            return {}, 204
        else:
            return {"message": "Unauthorized access."}, 401

class RecipeIndex(Resource):
    def get(self):
        if session['user_id']:
            recipes_dict = [recipe.to_dict() for recipe in Recipe.query.filter(session['user_id'] == Recipe.user_id).all()]
            return recipes_dict, 200
        else:
            return {"message": "Unauthorized access."}, 401
    
    def post(self):
        if session['user_id']:
            recipe_data = request.get_json()
            recipe = Recipe(
                title = recipe_data.get("title"),
                instructions = recipe_data.get("instructions"),
                minutes_to_complete = recipe_data.get("minutes_to_complete"),
                user_id = session['user_id']
            )
            try:
                db.session.add(recipe)
                db.session.commit()

                return recipe.to_dict(), 201
            except IntegrityError:
                return {"message": "Recipe is not valid."}, 422
        else:
            return {"message": "You are not logged in."}, 401

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)