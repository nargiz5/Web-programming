<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
</head>
<body>
<h1>Login</h1>
<form action="login" method="POST">
    <label>Username:</label><br>
    <input type="text" name="username"><br>
    <label>Password:</label><br>
    <input type="password" name="password"><br>
    <button type="submit">Login</button>
</form>
<%--<p style="color: red;"><%= request.getParameter("error") %></p>--%>
</body>
</html>
