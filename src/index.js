import jwt from '@tsndr/cloudflare-worker-jwt'

export default {
    async fetch(request, env) {
        return await handleRequest(request, env)
    }
}

async function handleRequest(request, env) {
    const url = new URL(request.url)
    const path = url.pathname
    const method = request.method
    const isValid = await isValidJwt(request, env);

    if (!isValid) {
        return new Response('Invalid Token', { status: 401 })
    }

    if (path === '/filters' && method === 'GET') {
        return new Response(JSON.stringify(filters), {
            status: 200,
            headers: {
                'content-type': 'application/json;charset=UTF-8',
            }
        })
    }
    if (path === '/filters' && method === 'POST') {
        // Create a new user
        const filter = await request.json()
        filters.push(filter)
        return new Response(JSON.stringify(filter), { status: 201 })
    }
    if (path.startsWith('/filters/') && method === 'GET') {
        // Return a specific filter
        const filterId = path.split('/')[2]
        const filter = filters.find(filter => filter.id === filterId)
        if (!filter) {
            return new Response('', { status: 404 })
        }
        return new Response(JSON.stringify(filter))
    }
    if (path.startsWith('/filters/') && method === 'PUT') {
        // Update a specific filter
        const filterId = path.split('/')[2]
        const filterIndex = filters.findIndex(filter => filter.id === filterId)
        if (filterIndex === -1) {
            return new Response('', { status: 404 })
        }
        const updatedfilter = await request.json()
        filters[filterIndex] = updatedfilter
        return new Response(JSON.stringify(updatedfilter))
    }
    if (path.startsWith('/filters/') && method === 'DELETE') {
        // Delete a specific filter
        const filterId = path.split('/')[2]
        const filterIndex = filters.findIndex(filter => filter.id === filterId)
        if (filterIndex === -1) {
            return new Response('', { status: 404 })
        }
        filters.splice(filterIndex, 1)
        return new Response('', { status: 204 })
    }

    // Unrecognized path or method
    return new Response('', { status: 404 })
}

async function isValidJwt(request, env) {
    const encodedToken = getJwt(request, env);
    if (encodedToken === null) {
        return false
    }
    return verifyToken(encodedToken, env)
}

function getJwt(request, env) {
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || authHeader.substring(0, 6) !== 'Bearer') {
        return null
    }
    return authHeader.substring(6).trim()
}

async function getJWK(env) {
    const res = await fetch(`https://${env.AUTH0_DOMAIN}/.well-known/jwks.json`);
    const jwk = await res.json();
    return jwk;
}

async function verifyToken(token, env) {
    if (!token) {
        return false;
    }

    const decodedToken = jwt.decode(token, { complete: true });
    const jwk = await getJWK(env);
    // console.log(decodedToken?.header);
    // console.log(decodedToken?.payload);

    let cert = jwk.keys[0].x5c[0];
    cert = cert.match(/.{1,64}/g).join('\n');
    cert = `-----BEGIN CERTIFICATE-----\n${cert}\n-----END CERTIFICATE-----\n`;

    if (jwk.keys[0].kid === decodedToken?.header?.kid) {
        try {
            jwt.verify(token, cert);
            return true;
        } catch (error) {
            return false;
        }
    }

    return false;
}


const filters = [
    {
        "label": "Property condition2",
        "key": "_condition",
        "type": "checkbox",
        "searchable": false,
        "isMulti": true,
        "options": [
            {
                "label": "Managed",
                "value": "managed"
            },
            {
                "label": "Not Managed",
                "value": "notManaged"
            },
            {
                "label": "Expiring Certificate",
                "value": "expiringCertificate"
            },
            {
                "label": "Expired Certificate",
                "value": "expiredCertificate"
            }
        ]
    },
    {
        "label": "Property type",
        "key": "property_type_id",
        "type": "checkbox",
        "searchable": false,
        "isMulti": true,
        "options": [
            {
                "label": "Residential",
                "value": 1
            },
            {
                "label": "Mixed",
                "value": 3
            },
            {
                "label": "Residential Block",
                "value": 10
            }
        ]
    },
    {
        "label": "Contains",
        "key": "_property_description",
        "type": "checkbox",
        "searchable": false,
        "isMulti": true,
        "options": [
            {
                "label": "Single Unit",
                "value": 2
            },
            {
                "label": "Multiple Units",
                "value": 3
            }
        ]
    }
]