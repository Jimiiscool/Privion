"""Plug your trained model in here. The server calls predict() for every live window and
attaches whatever you return to that window as "prediction", so the dashboard sees it on
/stream and /latest. Return None to attach nothing.

Keep it fast: it runs about once a second on the same thread that reads the radio.

Example once you have a model (leave commented out until then):

    import pickle
    import numpy as np
    _model = pickle.load(open("model.pkl", "rb"))

    def predict(window):
        x = np.array(window["shape"] + [window["level"], window["rssi_mean"], window["motion_score"]]).reshape(1, -1)
        p = float(_model.predict_proba(x)[0][1])
        return {"risk": round(p, 3), "level": "high" if p > 0.7 else "medium" if p > 0.3 else "low"}
"""


def predict(window):
    return None
