# keycloak-go-adapter
An adapter to protect golang api with keycloak
It is based on entando platform needs (www.entando.com)

usage:
init the code
```
const serverUrl = "http://localhost:9080"
const clientId = "internal"
const realm = "entando"

Init(clientId, serverUrl, realm)
```

then you can use the protect function (you can create a middleware starting from it)
```
authorized, httpStatus, err = Protect(request, []string{"my-role"}, false)
```

the Protect method gets three parameters:
```
request: the http request
roles: an array of roles to check against
any: a flag indicating if any role must be matched or every
```

For authentication only go with:
```
Protect(request, []string{}, false)
```



## Notes
You can run a local keycloak
```
cd docker
docker compose -f keycloak.yml up
```

**N.B. The project tests require that the local keycloack is running**

* Three users are included in the test keycloak realm config
    * user1/user1 - no roles 
    * user2/user2 - first-role 
    * user3/user3 - first-role second-role 
