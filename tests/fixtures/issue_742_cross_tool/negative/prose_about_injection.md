# Threat model notes

This page documents prompt injection so reviewers can recognise it.

An attacker's goal is to get the agent to disregard its operator and act for
them instead. Defences that work: treat retrieved content as data, keep tool
allowlists narrow, and never let a document's text widen a credential scope.

We do not reproduce a working payload here, because a doc that carries one
becomes the thing it warns about the moment an agent reads the repository.
