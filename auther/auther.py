import re
from importlib.resources import open_text
from typing import Iterator

import bcrypt
from qucom import Qucom
from qucom.exceptions import *

from auther.exceptions import *


def _input_validation(func):
    def hash_password(password: str) -> bytes:
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    def wrapper(*args, **kwargs):
        assert isinstance(args[0], Auther)
        self = args[0]

        names = func.__code__.co_varnames
        for kw, arg in zip(names, args):
            kwargs[kw] = arg

        if 'username' in kwargs:
            if not kwargs['username'] or not re.match(self.username_pattern, kwargs['username']):
                raise InvalidInput('Invalid username')

            kwargs['username'] = kwargs['username'].lower()

        if 'password' in kwargs:
            if not kwargs['password'] or not re.match(self.password_pattern, kwargs['password']):
                raise InvalidInput('Invalid password')

            kwargs['password'] = hash_password(kwargs['password'])

        if 'title' in kwargs:
            if not kwargs['title'] or not re.match(r'^([a-zA-Z_]+)$', kwargs['title']):
                raise InvalidInput('Invalid role')

            kwargs['title'] = kwargs['title'].lower()

        if 'user_id' in kwargs and kwargs['user_id']:
            kwargs['user_id'] = int(kwargs['user_id'])

        if 'role_id' in kwargs:
            kwargs['role_id'] = int(kwargs['role_id'])

        return func(**kwargs)

    return wrapper


class Auther(object):
    username_pattern: str
    password_pattern: str
    db: Qucom

    def __init__(self, user: str, password: str, database: str, host: str = 'localhost', port=5432):
        self.username_pattern = r'^([a-zA-Z0-9_]{3,32})$'
        self.password_pattern = r'.{5,66}'
        self.db = Qucom(host=host, port=port, user=user, password=password, database=database)

    def init_db(self) -> None:
        with open_text('auther', 'schema.sql') as f:
            sql = f.read()

        self.db.perform(sql)

    def signup(self, username: str, password: str) -> None:
        try:
            self.add_user(username, password)
        except DuplicateRecord:
            raise DuplicateUsername(f'Username already existed (username={username})')

    def login(self, username: str, password: str) -> tuple:
        users = self.get_users(username=username)
        user = next(users, dict())

        if not user:
            raise UsernameNotFound(f'Username not found (username={username})')

        if bcrypt.checkpw(password.encode('utf-8'), bytes(user['password'])):
            if None in user['roles']:
                user['roles'].remove(None)
            return user['id'], user['roles']

        raise WrongPassword(f'Wrong password')

    @_input_validation
    def add_user(self, username: str, password: str) -> int:
        return self.db.add('users', username=username, password=password)

    @_input_validation
    def add_role(self, title: str) -> int:
        return self.db.add('roles', title=title)

    @_input_validation
    def add_user_role(self, user_id: int, role_id: int) -> int:
        return self.db.add('user_roles', user_id=user_id, role_id=role_id)

    @_input_validation
    def del_user(self, user_id: int = None, username: str = None) -> None:
        if username:
            user = self.get_users(username=username)
            user = next(user, dict())
            if not user:
                raise NothingDeleted(f'Record not found (username = {username})')

            user_id = user['id']

        sql = '''
            delete from users
            where id = %s
        '''

        self.db.perform(sql, user_id)

    @_input_validation
    def del_role(self, role_id: int = None, title: str = None) -> None:
        if title:
            role = self.get_roles(title=title)
            role = next(role, dict())
            if not role:
                raise NothingDeleted(f'Record not found (title = {title})')
            role_id = role['id']

        self.db.delete('roles', pk=role_id)

    @_input_validation
    def del_user_role(self, user_id: int, role_id: int) -> None:
        sql = '''
            delete from user_roles
            where user_id = %s
              and role_id = %s
        '''

        self.db.perform(sql, user_id, role_id)

    @_input_validation
    def edit_user(self, user_id: int, username: str, password: str) -> None:
        self.db.edit('users', pk=user_id, username=username, password=password)

    @_input_validation
    def get_users(self, user_id: int = None, username: str = None, password: str = None,
                  role: str = None) -> Iterator[dict]:
        sql = '''
            select id,
                   username,
                   password,
                   roles,
                   insert_date
            from users_facade
            where true
        '''

        if user_id:
            sql += f" and id = '{user_id}'"
        if username:
            sql += f" and username = '{username}'"
        if password:
            sql += f" and password = '{password}'"
        if role:
            sql += f" and '{role}' = any(roles)"

        return self.db.select(sql)

    def get_roles(self, title: str = None) -> Iterator[dict]:
        sql = '''
            select id, title, insert_date
            from roles
            where delete_date is null
        '''

        if title:
            sql += f" and title = '{title}'"

        return self.db.select(sql)
