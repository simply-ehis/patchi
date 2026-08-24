import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart' as io;
import 'dart:convert';

class User {
  final int id;
  final String name;
  final String email;

  User({required this.id, required this.name, required this.email});

  Map<String, dynamic> toJson() => {'id': id, 'name': name, 'email': email};
}

List<User> users = [];
int nextId = 1;

Future<void> main() async {
  final handler = const Pipeline()
      .addMiddleware(logRequests())
      .addHandler(_router);

  final server = await io.serve(handler, InternetAddress.anyIPv4, 8080);
  print('Server running on port ${server.port}');
}

Future<Response> _router(Request request) async {
  if (request.method == 'GET' && request.url.path == 'users') {
    return _getUsers();
  }
  if (request.method == 'POST' && request.url.path == 'users') {
    return _createUser(request);
  }
  if (request.method == 'GET' && request.url.pathSegments.first == 'users') {
    final id = int.tryParse(request.url.pathSegments.last);
    return _getUser(id);
  }
  if (request.method == 'DELETE' && request.url.pathSegments.first == 'users') {
    final id = int.tryParse(request.url.pathSegments.last);
    return _deleteUser(id);
  }
  if (request.method == 'GET' && request.url.path == 'search') {
    return _search(request);
  }
  return Response.notFound('Not found');
}

Response _getUsers() {
  return Response.ok(jsonEncode({'items': users, 'count': users.length}));
}

Response _getUser(int? id) {
  final user = users.firstWhere((u) => u.id == id, orElse: () => User(id: 0, name: '', email: ''));
  if (user.id == 0) return Response.notFound(jsonEncode({'error': 'Not found'}));
  return Response.ok(jsonEncode({'item': user.toJson()}));
}

Future<Response> _createUser(Request request) async {
  final body = jsonDecode(await request.readAsString());
  final user = User(id: nextId++, name: body['name'], email: body['email']);
  users.add(user);
  return Response(201, body: jsonEncode({'item': user.toJson()}));
}

Response _deleteUser(int? id) {
  users.removeWhere((u) => u.id == id);
  return Response.ok(jsonEncode({'message': 'Deleted'}));
}

Response _search(Request request) {
  final query = request.url.queryParameters['q'] ?? '';
  final results = users.where((u) => u.name.contains(query)).toList();
  return Response.ok(jsonEncode({'results': results}));
}

String unusedFunction() {
  return 'dead code';
}
