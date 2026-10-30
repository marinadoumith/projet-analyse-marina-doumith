"""Projet 1 - Analyse des journaux d'un pare-feu.

Lancer avec : python analyse.py
Lit data/logs_reseau.csv, nettoie les donnees, calcule les resultats,
enregistre les figures dans figures/ et ecrit resultats.json.
"""
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")  # pas besoin d'ecran
import matplotlib.pyplot as plt
import pandas as pd

RACINE = Path(__file__).resolve().parent
CSV = RACINE / "data" / "logs_reseau.csv"
DOSSIER_FIGURES = RACINE / "figures"
SORTIE_JSON = RACINE / "resultats.json"


def charger_et_nettoyer(chemin):
    df = pd.read_csv(chemin)

    # 1. doublons exacts
    df = df.drop_duplicates()

    # 2. protocol en MAJUSCULES (on retire aussi les espaces parasites)
    df["protocol"] = df["protocol"].astype("string").str.strip().str.upper()

    # 3. bytes_sent manquants -> mediane (calculee apres suppression des doublons)
    df["bytes_sent"] = pd.to_numeric(df["bytes_sent"], errors="coerce")
    df["bytes_sent"] = df["bytes_sent"].fillna(df["bytes_sent"].median())

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df


def calculer_resultats(df):
    # Si 'action' a une casse incoherente, on la normalise pour le calcul seulement
    action = df["action"].astype("string").str.strip().str.upper()
    return {
        "nb_lignes_apres_nettoyage": int(len(df)),
        "top_port": int(df["dst_port"].value_counts().idxmax()),
        "taux_deny_pct": round(float((action == "DENY").mean() * 100), 2),
        "ip_scanner": str(df.groupby("src_ip")["dst_port"].nunique().idxmax()),
        "ip_exfiltration": str(df.groupby("src_ip")["bytes_sent"].sum().idxmax()),
    }


def faire_figures(df):
    DOSSIER_FIGURES.mkdir(exist_ok=True)
    action = df["action"].astype("string").str.strip().str.upper()

    # Figure 1 : top 10 des ports
    fig, ax = plt.subplots(figsize=(8, 5))
    df["dst_port"].value_counts().head(10).plot(kind="bar", ax=ax, color="steelblue")
    ax.set_title("Top 10 des ports de destination")
    ax.set_xlabel("Port de destination")
    ax.set_ylabel("Nombre de connexions")
    plt.xticks(rotation=0)
    fig.tight_layout()
    fig.savefig(DOSSIER_FIGURES / "top_ports.png", dpi=120)
    plt.close(fig)

    # Figure 2 : connexions par heure
    fig, ax = plt.subplots(figsize=(8, 5))
    df["timestamp"].dt.hour.value_counts().sort_index().plot(kind="bar", ax=ax, color="darkorange")
    ax.set_title("Connexions par heure de la journee")
    ax.set_xlabel("Heure")
    ax.set_ylabel("Nombre de connexions")
    fig.tight_layout()
    fig.savefig(DOSSIER_FIGURES / "connexions_par_heure.png", dpi=120)
    plt.close(fig)

    # Figure 3 : volume d'octets par type d'appareil
    fig, ax = plt.subplots(figsize=(8, 5))
    df.groupby("device_type")["bytes_sent"].sum().sort_values().plot(kind="barh", ax=ax, color="seagreen")
    ax.set_title("Volume d'octets envoyes par type d'appareil")
    ax.set_xlabel("Octets envoyes (total)")
    ax.set_ylabel("Type d'appareil")
    fig.tight_layout()
    fig.savefig(DOSSIER_FIGURES / "octets_par_appareil.png", dpi=120)
    plt.close(fig)

    # Figure 4 : repartition ALLOW / DENY
    fig, ax = plt.subplots(figsize=(6, 6))
    action.value_counts().plot(kind="pie", ax=ax, autopct="%1.1f%%",
                               colors=["#4c9f70", "#d9534f"])
    ax.set_title("Repartition ALLOW / DENY")
    ax.set_ylabel("")
    fig.tight_layout()
    fig.savefig(DOSSIER_FIGURES / "allow_deny.png", dpi=120)
    plt.close(fig)

    # Figure 5 : top 10 IP par nombre de ports distincts (preuve du scan)
    fig, ax = plt.subplots(figsize=(8, 5))
    df.groupby("src_ip")["dst_port"].nunique().sort_values(ascending=False).head(10)[::-1].plot(
        kind="barh", ax=ax, color="firebrick")
    ax.set_title("Top 10 des IP sources par nombre de ports distincts contactes")
    ax.set_xlabel("Ports distincts")
    ax.set_ylabel("IP source")
    fig.tight_layout()
    fig.savefig(DOSSIER_FIGURES / "ip_ports_distincts.png", dpi=120)
    plt.close(fig)


def main():
    df = charger_et_nettoyer(CSV)
    resultats = calculer_resultats(df)
    faire_figures(df)
    with open(SORTIE_JSON, "w", encoding="utf-8") as f:
        json.dump(resultats, f, indent=2, ensure_ascii=False)
    print(json.dumps(resultats, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()