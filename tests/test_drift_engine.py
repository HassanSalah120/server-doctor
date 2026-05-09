from server_doctor.engine.drift import compare_models


def test_new_public_port_is_detected():
    before = {"network_surface": {"endpoints": []}}
    after = {
        "network_surface": {
            "endpoints": [
                {"protocol": "tcp", "port": 6379, "is_public": True},
            ]
        }
    }

    drift = compare_models(before, after)

    assert drift[0].kind == "public port"
    assert drift[0].after == "tcp/6379"


def test_same_ports_in_different_order_have_no_drift():
    before = {
        "network_surface": {
            "endpoints": [
                {"protocol": "tcp", "port": 80, "is_public": True},
                {"protocol": "tcp", "port": 443, "is_public": True},
            ]
        }
    }
    after = {
        "network_surface": {
            "endpoints": [
                {"protocol": "tcp", "port": 443, "is_public": True},
                {"protocol": "tcp", "port": 80, "is_public": True},
            ]
        }
    }

    assert compare_models(before, after) == []
