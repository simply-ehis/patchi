<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function all()
    {
        return User::all();
    }

    public function find($id)
    {
        return User::find($id);
    }

    public function create(array $data)
    {
        return User::create($data);
    }

    public function update(User $user, array $data)
    {
        $user->update($data);
        return $user;
    }

    public function delete(User $user)
    {
        return $user->delete();
    }

    public function search($query)
    {
        return User::where('name', 'LIKE', "%{$query}%")->get();
    }

    public function legacyMethod($data)
    {
        return $data;
    }
}
