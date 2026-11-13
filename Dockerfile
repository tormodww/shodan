FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build
# Versjon og byggetidspunkt, vises øverst i appen. Settes som build args av byggeinfo.sh (deploy.sh eller
# familiesidens oppdater-alle.sh). Uten dem lages ingen versjon.json, og appen viser ingen versjon.
ARG BYGG_COMMIT=""
ARG BYGG_COMMIT_DATO=""
ARG BYGG_PR=""
ARG BYGG_TID=""
RUN if [ -n "$BYGG_COMMIT" ]; then \
      case "$BYGG_PR" in ''|*[!0-9]*) pr=null ;; *) pr="$BYGG_PR" ;; esac; \
      printf '{"commit":"%s","commitDato":"%s","pr":%s,"bygget":"%s"}\n' \
        "$BYGG_COMMIT" "$BYGG_COMMIT_DATO" "$pr" "${BYGG_TID:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}" > dist/versjon.json; \
    fi

FROM nginx:stable-alpine
RUN apk add --no-cache ca-certificates
COPY docker/default.conf.template /etc/nginx/templates/default.conf.template
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
