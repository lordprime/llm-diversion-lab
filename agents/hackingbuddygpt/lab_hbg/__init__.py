"""The lab's hackingBuddyGPT use case, baked into the agent image as a plugin.

``python -m lab_hbg LabWebTesting --...`` runs it inside the image. Only
:mod:`.contract` is plain Python: the adapter and the tests import it here, outside the
image. :mod:`.usecase` and :mod:`.__main__` import hackingBuddyGPT, so they run only in
the image and this package must never import them.
"""
