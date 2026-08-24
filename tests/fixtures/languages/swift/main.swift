import Vapor

struct User: Content {
    var id: Int?
    var name: String
    var email: String
}

var users: [User] = []
var nextId = 1

@main
func configure(_ app: Application) throws {
    app.get("users") { req async throws -> [String: Any] in
        ["items": users, "count": users.count]
    }

    app.get("users", ":id") { req async throws -> User in
        guard let id = req.parameters.get("id", as: Int.self),
              let user = users.first(where: { $0.id == id }) else {
            throw Abort(.notFound)
        }
        return user
    }

    app.post("users") { req async throws -> User in
        var user = try req.content.decode(User.self)
        user.id = nextId
        nextId += 1
        users.append(user)
        return user
    }

    app.put("users", ":id") { req async throws -> User in
        guard let id = req.parameters.get("id", as: Int.self),
              let index = users.firstIndex(where: { $0.id == id }) else {
            throw Abort(.notFound)
        }
        var updated = try req.content.decode(User.self)
        updated.id = id
        users[index] = updated
        return updated
    }

    app.delete("users", ":id") { req async throws -> [String: String] in
        guard let id = req.parameters.get("id", as: Int.self) else {
            throw Abort(.notFound)
        }
        users.removeAll { $0.id == id }
        return ["message": "Deleted"]
    }

    app.get("search") { req async throws -> [String: Any] in
        let query = req.query["q"] ?? ""
        let results = users.filter { $0.name.contains(query) }
        return ["results": results]
    }
}

func unusedFunction() -> String {
    return "dead code"
}
