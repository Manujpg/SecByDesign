"""Basisklasse für alle Eingabe-Schemas (SR-04).

- ``extra="forbid"``: unbekannte Felder führen zu 422 statt still ignoriert zu werden
  (verhindert z. B. das Einschleusen von ``role`` bei der Registrierung).
- Whitespace wird abgeschnitten, damit Längenprüfungen auf dem echten Inhalt greifen.
"""

from pydantic import BaseModel, ConfigDict


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, frozen=True)
