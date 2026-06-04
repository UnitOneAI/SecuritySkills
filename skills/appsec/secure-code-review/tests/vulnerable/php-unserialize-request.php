<?php

// VULNERABLE: attacker-controlled request data reaches PHP native deserialization.
$state = $_POST['state'] ?? '';
$profile = unserialize($state);

echo $profile->displayName ?? 'guest';
