#!/usr/bin/env bash
set -euo pipefail
docker context use rancher-desktop
cd "$(dirname "$0")"

usage() {
  echo "Usage: $0 [up|down|build|restart|logs|ps]"
  echo ""
  echo "  up        Build et démarre les conteneurs (défaut)"
  echo "  down      Arrête et supprime les conteneurs"
  echo "  build     Rebuild les images sans démarrer"
  echo "  restart   Redémarre les conteneurs"
  echo "  logs      Affiche les logs en temps réel"
  echo "  ps        Statut des conteneurs"
}

CMD="${1:-up}"

case "$CMD" in
  up)
    echo "→ Build et démarrage des conteneurs..."
    docker compose build
    docker compose up -d
    echo ""
    echo "✓ Disponible sur http://localhost"
    echo "  Backend API : http://localhost/api"
    echo "  Logs : $0 logs"
    ;;
  down)
    echo "→ Arrêt des conteneurs..."
    docker compose down
    ;;
  build)
    echo "→ Build des images..."
    docker compose build
    echo "✓ Images construites"
    ;;
  restart)
    echo "→ Redémarrage des conteneurs..."
    docker compose restart
    ;;
  logs)
    docker compose logs -f
    ;;
  ps)
    docker compose ps
    ;;
  *)
    echo "Commande inconnue : $CMD"
    usage
    exit 1
    ;;
esac
