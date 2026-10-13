from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def _page_frame(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(colors.HexColor("#b8d2c3"))
    canvas.setLineWidth(.35)
    canvas.line(18*mm, 13*mm, A4[0] - 18*mm, 13*mm)
    canvas.setFont("Helvetica", 6.5)
    canvas.setFillColor(colors.HexColor("#557064"))
    canvas.drawString(18*mm, 9*mm, "NULL//SENTRY  //  SECURITY REPORT  //  CONFIDENTIAL")
    canvas.drawRightString(A4[0] - 18*mm, 9*mm, f"PAGE {doc.page}")
    canvas.restoreState()


def build_pdf(item: dict) -> BytesIO:
    stream = BytesIO()
    doc = SimpleDocTemplate(stream, pagesize=A4, rightMargin=18*mm, leftMargin=18*mm, topMargin=17*mm, bottomMargin=17*mm, title=f"NULL//SENTRY — {item['project']}")
    base = getSampleStyleSheet()
    title = ParagraphStyle("TitleDark", parent=base["Title"], fontName="Helvetica-Bold", fontSize=24, leading=28, textColor=colors.HexColor("#073b24"), alignment=TA_CENTER, spaceAfter=8)
    h2 = ParagraphStyle("H2", parent=base["Heading2"], fontName="Helvetica-Bold", fontSize=13, textColor=colors.HexColor("#087443"), spaceBefore=12, spaceAfter=7)
    body = ParagraphStyle("Body", parent=base["BodyText"], fontName="Helvetica", fontSize=9, leading=13, textColor=colors.HexColor("#23352c"))
    small = ParagraphStyle("Small", parent=body, fontSize=7, leading=10, textColor=colors.HexColor("#5a6d63"))
    result = item.get("result", {})
    findings = result.get("findings", [])
    story = [Paragraph("NULL//SENTRY", title), Paragraph("SECURITY OPERATIONS REPORT", ParagraphStyle("Sub", parent=small, alignment=TA_CENTER, letterSpacing=2)), Spacer(1, 10*mm)]
    summary = [["Projeto", escape(item["project"])], ["Data", escape(item["created"])], ["Security Gate", escape(result.get("gate", item["status"]))], ["Tipo", escape(result.get("scan_type", "code").upper())], ["Achados", str(len(findings))]]
    table = Table(summary, colWidths=[42*mm, 112*mm])
    table.setStyle(TableStyle([("BACKGROUND",(0,0),(0,-1),colors.HexColor("#082d1c")),("TEXTCOLOR",(0,0),(0,-1),colors.HexColor("#6dffb5")),("TEXTCOLOR",(1,0),(1,-1),colors.HexColor("#17291f")),("GRID",(0,0),(-1,-1),.4,colors.HexColor("#a9c8b7")),("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),("FONTNAME",(1,0),(1,-1),"Helvetica"),("FONTSIZE",(0,0),(-1,-1),8),("VALIGN",(0,0),(-1,-1),"MIDDLE"),("PADDING",(0,0),(-1,-1),7)]))
    story += [table, Spacer(1, 6*mm)]
    ai = result.get("ai_report")
    if ai:
        story += [Paragraph("Análise executiva Codex", h2), Paragraph(escape(ai.get("summary", "")), body), Spacer(1, 2*mm), Paragraph("Prioridades", h2), Paragraph(escape(ai.get("priorities", "")), body), Spacer(1, 2*mm), Paragraph("Plano recomendado", h2), Paragraph(escape(ai.get("action_plan", "")).replace("\n", "<br/>"), body)]
    else:
        story += [Paragraph("Resumo executivo", h2), Paragraph("Relatório técnico gerado sem resumo de IA.", body)]
    story += [Spacer(1, 7*mm), Paragraph("Achados técnicos", h2)]
    if not findings:
        story.append(Paragraph("Nenhum achado pelas regras executadas. Isso não garante ausência de vulnerabilidades.", body))
    for index, finding in enumerate(findings, 1):
        story += [Paragraph(f"{index:02d} / {escape(finding['severity'])} / {escape(finding['rule'])} — {escape(finding['title'])}", h2), Paragraph(f"<b>Local:</b> {escape(str(finding['file']))}:{finding.get('line',1)} &nbsp; <b>CWE:</b> {escape(finding['cwe'])} &nbsp; <b>Engine:</b> {escape(finding.get('engine',''))}", small), Spacer(1, 1.5*mm), Paragraph(escape(finding["remediation"]), body)]
        review = finding.get("ai")
        if review:
            story += [Spacer(1, 1.5*mm), Paragraph("Revisão Codex: " + escape(review.get("explanation", "")), small)]
    story += [Spacer(1, 8*mm), Paragraph("Gerado por NULL//SENTRY. Revise os achados manualmente antes de tomar decisões de segurança.", small)]
    doc.build(story, onFirstPage=_page_frame, onLaterPages=_page_frame)
    stream.seek(0)
    return stream
