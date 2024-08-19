import requests
import json

# Define the GraphQL introspection query
introspection_query = """
{
  __schema {
    types {
      name
      fields {
        name
        type {
          name
          kind
        }
        args {
          name
          type {
            name
            kind
          }
        }
      }
      kind
    }
  }
}
"""

# URL of the GraphQL endpoint
graphql_endpoint = 'https://hackerone.com/graphql'


def get_graphql_schema(endpoint, query):
    headers = {
        'Content-Type': 'application/json'
    }

    response = requests.post(endpoint, headers=headers, json={'query': query})

    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Query failed with status code {response.status_code}: {response.text}")


if __name__ == "__main__":
    try:
        schema = get_graphql_schema(graphql_endpoint, introspection_query)
        print(json.dumps(schema, indent=2))
        file1 = open("C:\\Users\\vishr\\PycharmProjects\\HackerOneScrape\\MyFile1.txt", "a")
        file1.write(json.dumps(schema, indent=2))
        file1.close()
    except Exception as e:
        print(f"Error fetching schema: {e}")