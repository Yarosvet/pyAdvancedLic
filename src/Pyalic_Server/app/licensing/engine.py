"""
Wrapper to easily use licensing engine
"""
from datetime import datetime, timedelta
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import models
from . import exceptions
from .sessions import search_sessions, create_session


async def check_and_start_session(license_key: str, fingerprint: str, session: AsyncSession) -> str:
    """

    :param license_key: Client's license key
    :param fingerprint: Client's fingerprint
    :param session: AsyncSession of database
    :return: SessionID
    """
    # Get signature
    r = await session.execute(select(models.Signature).filter_by(license_key=license_key).options(
        selectinload(models.Signature.product), selectinload(models.Signature.installations)))
    if (sig := r.scalar_one_or_none()) is None:
        raise exceptions.InvalidKeyException()
    # Check license period
    current_period = datetime.utcnow() - sig.activation_date if sig.activation_date is not None else timedelta(
        seconds=0)
    if sig.product.sig_period is not None and sig.product.sig_period < current_period:
        raise exceptions.LicenseExpiredException()
    # Check installation limit
    current_inst = None
    if sig.product.sig_install_limit is not None:
        r = await session.execute(select(models.Installation).filter_by(signature_id=sig.id, fingerprint=fingerprint))
        current_inst = r.scalar_one_or_none()
        if current_inst is None and len(sig.installations) >= sig.product.sig_install_limit:
            raise exceptions.InstallationsLimitException
    # Check sessions limit
    if sig.product.sig_sessions_limit is not None and \
            len(await search_sessions(sig.id)) >= sig.product.sig_sessions_limit:
        raise exceptions.SessionsLimitException()
    # If all Ok, activate Signature if needed
    if sig.activation_date is None:
        sig.activation_date = datetime.utcnow()
    # And register installation if it's a new one
    if current_inst is None:
        current_inst = models.Installation(signature_id=sig.id, fingerprint=fingerprint)
        session.add(current_inst)
        await session.commit()
    # Start a new session for this signature
    sig_ends = int((sig.product.sig_period + sig.activation_date).timestamp()) \
        if sig.product.sig_period is not None else None
    return await create_session(sig.id, signature_ends=sig_ends)
