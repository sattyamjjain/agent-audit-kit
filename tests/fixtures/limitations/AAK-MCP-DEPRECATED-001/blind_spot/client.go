package main

func listRoots(c Client) {
	c.Request("roots/list")
}
