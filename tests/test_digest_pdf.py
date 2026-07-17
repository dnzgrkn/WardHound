from datetime import UTC, datetime, timedelta

import pytest

from app.digest_pdf import render_digest_pdf
from app.schemas.digest import AggregateStat, DailyDigest, DigestNarrative


@pytest.mark.parametrize("with_narrative", [False, True])
def test_render_digest_pdf_returns_valid_non_empty_document(with_narrative: bool) -> None:
    start = datetime(2026, 7, 16, 12, tzinfo=UTC)
    narrative = (
        DigestNarrative(
            executive_summary="Synthetic daily security activity remained within expectations.",
            highlights=["One synthetic high-severity incident was retained."],
            recommended_follow_up=["Review the retained incident through WardHound."],
        )
        if with_narrative
        else None
    )
    digest = DailyDigest(
        period_start=start,
        period_end=start + timedelta(days=1),
        incidents=[],
        aggregate_stats=[
            AggregateStat(name="incidents_by_severity", label="high", count=1)
        ],
        narrative=narrative,
    )

    rendered = render_digest_pdf(digest)

    assert rendered.startswith(b"%PDF-")
    assert rendered.rstrip().endswith(b"%%EOF")
    assert len(rendered) > 1_000
