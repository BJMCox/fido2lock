#compdef fido2lock

_fido2lock() {
  local -a commands
  commands=(
    'enroll-key:enroll the inserted security key'
    'remove-key:remove enrolled keys'
    'check-key:show whether the inserted key is enrolled'
    'list-keys:list the labels of the enrolled keys'
    'completions:print a shell completion script'
    'help:show the commands and options'
  )
  if (( CURRENT == 2 )); then
    if [[ $PREFIX == -* ]]; then
      compadd -- --help -h
    else
      _describe 'command' commands
    fi
    return
  fi
  case $words[2] in
    enroll-key)
      (( CURRENT == 3 )) && compadd -- --label
      ;;
    remove-key)
      # --label NAME repeats, so odd words are --label and even words are key labels.
      if (( CURRENT % 2 )); then
        compadd -- --label
      else
        compadd -- ${(f)"$(fido2lock list-keys 2>/dev/null)"}
      fi
      ;;
    completions)
      (( CURRENT == 3 )) && compadd zsh
      ;;
  esac
}

# Works both as an autoloaded file in $fpath and with `source <(fido2lock completions zsh)`.
if [[ $zsh_eval_context[-1] == loadautofunc ]]; then
  _fido2lock "$@"
else
  compdef _fido2lock fido2lock
fi
