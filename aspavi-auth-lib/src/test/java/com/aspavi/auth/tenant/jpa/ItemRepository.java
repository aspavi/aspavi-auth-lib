package com.aspavi.auth.tenant.jpa;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

/** Query methods declared like the services do: none of them is {@code @Transactional}. */
public interface ItemRepository extends JpaRepository<Item, Integer> {

    List<Item> findByNameStartingWithOrderByName(String prefix);

    long countByNameStartingWith(String prefix);

    Optional<Item> findOneByNameStartingWith(String prefix);

    long deleteByName(String name);

    @Query("select count(i) from Item i")
    long countAllItems();

    @Query(value = "SELECT name FROM item WHERE name LIKE :prefix || '%' ORDER BY name", nativeQuery = true)
    List<String> namesStartingWith(@Param("prefix") String prefix);
}
