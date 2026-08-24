import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.request.*

data class User(val id: Int, val name: String, val email: String)

val users = mutableListOf<User>()
var nextId = 1

fun main() {
    embeddedServer(Netty, port = 8080) {
        routing {
            get("/users") {
                call.respond(mapOf("items" to users, "count" to users.size))
            }
            get("/users/{id}") {
                val id = call.parameters["id"]?.toIntOrNull()
                val user = users.find { it.id == id }
                if (user != null) {
                    call.respond(mapOf("item" to user))
                } else {
                    call.respond(mapOf("error" to "Not found"))
                }
            }
            post("/users") {
                val user = User(nextId++, "name", "email@example.com")
                users.add(user)
                call.respond(mapOf("item" to user))
            }
            delete("/users/{id}") {
                val id = call.parameters["id"]?.toIntOrNull()
                users.removeAll { it.id == id }
                call.respond(mapOf("message" to "Deleted"))
            }
            get("/search") {
                val query = call.request.queryParameters["q"] ?: ""
                val results = users.filter { it.name.contains(query) }
                call.respond(mapOf("results" to results))
            }
        }
    }.start(wait = true)
}

fun unusedFunction(): String {
    return "dead code"
}
