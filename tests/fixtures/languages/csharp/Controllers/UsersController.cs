using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.Linq;

namespace Demo.Controllers;

[ApiController]
[Route("api/[controller]")]
public class UsersController : ControllerBase
{
    private static readonly List<User> _users = new();
    private static int _nextId = 1;

    [HttpGet]
    public ActionResult<IEnumerable<User>> GetAll()
    {
        return Ok(new { items = _users, count = _users.Count });
    }

    [HttpGet("{id}")]
    public ActionResult<User> GetById(int id)
    {
        var user = _users.FirstOrDefault(u => u.Id == id);
        if (user == null) return NotFound(new { error = "Not found" });
        return Ok(new { item = user });
    }

    [HttpPost]
    public ActionResult<User> Create(User user)
    {
        user.Id = _nextId++;
        _users.Add(user);
        return CreatedAtAction(nameof(GetById), new { id = user.Id }, new { item = user });
    }

    [HttpPut("{id}")]
    public ActionResult<User> Update(int id, User updated)
    {
        var user = _users.FirstOrDefault(u => u.Id == id);
        if (user == null) return NotFound(new { error = "Not found" });
        user.Name = updated.Name;
        user.Email = updated.Email;
        return Ok(new { item = user });
    }

    [HttpDelete("{id}")]
    public ActionResult Delete(int id)
    {
        var user = _users.FirstOrDefault(u => u.Id == id);
        if (user == null) return NotFound(new { error = "Not found" });
        _users.Remove(user);
        return Ok(new { message = "Deleted" });
    }

    [HttpGet("search")]
    public ActionResult Search([FromQuery] string q)
    {
        var results = _users.Where(u => u.Name.Contains(q)).ToList();
        return Ok(new { results });
    }

    private void UnusedHelper()
    {
    }
}

public class User
{
    public int Id { get; set; }
    public string Name { get; set; } = "";
    public string Email { get; set; } = "";
}
