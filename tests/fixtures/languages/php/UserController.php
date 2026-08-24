<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Services\UserService;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;

class UserController extends Controller
{
    protected $userService;

    public function __construct(UserService $userService)
    {
        $this->userService = $userService;
    }

    public function index()
    {
        $users = $this->userService->all();
        return response()->json(['items' => $users, 'count' => count($users)]);
    }

    public function show($id)
    {
        $user = $this->userService->find($id);
        if (!$user) {
            return response()->json(['error' => 'Not found'], 404);
        }
        return response()->json(['item' => $user]);
    }

    public function store(Request $request)
    {
        $validated = $request->validate([
            'name' => 'required|string',
            'email' => 'required|email|unique:users',
        ]);
        $user = $this->userService->create($validated);
        return response()->json(['item' => $user], 201);
    }

    public function update(Request $request, $id)
    {
        $user = $this->userService->find($id);
        if (!$user) {
            return response()->json(['error' => 'Not found'], 404);
        }
        $validated = $request->validate([
            'name' => 'sometimes|string',
            'email' => 'sometimes|email|unique:users,email,' . $id,
        ]);
        $this->userService->update($user, $validated);
        return response()->json(['item' => $user]);
    }

    public function destroy($id)
    {
        $user = $this->userService->find($id);
        if (!$user) {
            return response()->json(['error' => 'Not found'], 404);
        }
        $this->userService->delete($user);
        return response()->json(['message' => 'Deleted']);
    }

    public function search(Request $request)
    {
        $query = $request->input('q', '');
        $users = $this->userService->search($query);
        return response()->json(['results' => $users]);
    }

    private function unusedHelper()
    {
        return null;
    }
}
