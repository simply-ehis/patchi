package com.example.demo

import scala.concurrent.Future
import scala.util.{Success, Failure}
import akka.http.scaladsl.server.Directives._
import spray.json.DefaultJsonProtocol

trait UserRepository {
    def findById(id: Long): Future[Option[User]]
    def findAll(): Future[List[User]]
}

case class User(id: Long, name: String, email: String)

object UserService extends DefaultJsonProtocol {
    implicit val userFormat = jsonFormat3(User)

    def greet(name: String): String = s"Hello, $name!"

    private def validate(email: String): Boolean =
        email.contains("@")
}

class UserController(repo: UserRepository) {
    import system.dispatcher

    val routes = pathPrefix("users") {
        get {
            path(LongNumber) { id =>
                complete(repo.findById(id))
            }
        }
    }
}
