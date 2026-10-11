import neo4j

DRIVER = neo4j.GraphDatabase
QUERY = "CALL apoc.cypher.runWrite('CREATE (n)', {})"
