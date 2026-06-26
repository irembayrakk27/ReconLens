from packaging import version


def version_in_range(
    target_version,
    start_version=None,
    end_version=None
):
    """
    target_version:
        Sistemde bulunan versiyon

    start_version:
        Etkilenen minimum versiyon

    end_version:
        Etkilenen maksimum versiyon
    """

    try:

        target = version.parse(target_version)

        if start_version:

            start = version.parse(start_version)

            if target < start:
                return False

        if end_version:

            end = version.parse(end_version)

            if target > end:
                return False

        return True

    except Exception:

        return False