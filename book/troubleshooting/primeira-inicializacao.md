# A primeira inicialização: o que a luz significa

*(Este é o encarte do vendedor — pode ser impresso e entregue com a chave.
Nenhuma palavra técnica aqui; os detalhes completos estão em
[Troubleshooting the boot](./boot.md).)*

Na **primeira vez** que a chave é conectada numa porta USB, a luzinha faz
coisas que parecem estranhas. Nada disso é defeito. É assim:

## O que você vai ver

| A luz | O que significa |
|---|---|
| Piscadas curtas em grupos, no começo | a chave está ligando — normal |
| Uma **luz rápida piscando por alguns segundos** (com grupinhos extra a cada ~5 segundos) | a chave está **funcionando** — ela está se preparando. Na versão atual leva poucos segundos. **Espere.** Não precisa fazer nada |
| A luz fica piscando devagar, 1 vez por segundo, e continua assim | **pronta** — a inicialização terminou. Pode usar |
| **Piscando rápido por muitos minutos, sem parar** | só acontece nas **versões antigas** (v0.7.0/v0.7.1) — um defeito de primeira inicialização, já corrigido. **Atualize o firmware** da chave; ela não perdeu nada |
| **Uma luz longa (~1 segundo) e depois tudo escuro** | a chave está dizendo por que parou. **Tire da USB, espere 5 segundos, conecte de novo.** Se repetir, anote o padrão das piscadas e procure o suporte |

## A regra de bolso

- **Piscando rápido por alguns segundos = funcionando.** Espere.
- **Luz longa e depois escuro = tira, espera 5 s, conecta de novo.** Se
  repetir, suporte.
- **Piscando rápido por muitos minutos = versão antiga. Atualize o
  firmware** — nas versões atuais isso não acontece.
- **Depois de uma inicialização completa isso nunca mais acontece.** É só na
  primeira vez: a chave guarda o que precisava guardar, e nas próximas vezes
  liga rapidinho, mesmo depois de muito tempo desligada.

## Se piscar rápido por mais de ~5 minutos

Nas versões atuais isso não deveria acontecer — desligue da tomada (tire da
USB), espere 5–10 segundos, conecte de novo. Não perde nada — a chave só
estava esperando. Se piscar rápido em **toda** inicialização (e não só na
primeira), procure o suporte: isso sim é um sinal de hardware.
