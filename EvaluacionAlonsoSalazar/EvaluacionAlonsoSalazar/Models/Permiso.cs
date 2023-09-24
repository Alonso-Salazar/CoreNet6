using System;
using System.Collections.Generic;

namespace EvaluacionAlonsoSalazar.Models;

public partial class Permiso
{
    public int PermisoId { get; set; }

    public string? PermisoNombre { get; set; }

    public virtual ICollection<Person> BusinessEntities { get; set; } = new List<Person>();
}
