package com.gerenciador.tarefas.entity;

import jakarta.persistence.*;

import java.util.List;
import java.io.Serializable;

@Entity
@Table(name="usuarios")
public class Usuario implements Serializable {

    private static final long serialVersionUID = 1L;

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE)
    private Long id;

    @Column(unique = true,length = 50)
    private String username;

    @Column(unique = true,length = 50)
    private String password;

    @ManyToMany(fetch = FetchType.LAZY, cascade = CascadeType.ALL)
    @JoinTable(name="usuarios_roles", joinColumns = @JoinColumn(name="usuario_id"),
            inverseJoinColumns = @JoinColumn(name="role_id"),
            uniqueConstraints = @UniqueConstraint(columnNames={"usuario_id","role_id"}))
    private List<Role> roles;

}
