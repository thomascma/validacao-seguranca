package com.devsuperior.bds04.services;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.devsuperior.bds04.dto.EventDTO;
import com.devsuperior.bds04.entities.City;
import com.devsuperior.bds04.entities.Event;
import com.devsuperior.bds04.repositories.CityRepository;
import com.devsuperior.bds04.repositories.EventRepository;

import jakarta.persistence.EntityNotFoundException;

@Service
public class EventService {

	private final EventRepository eventRepository;
	private final CityRepository cityRepository;

	public EventService(EventRepository eventRepository, CityRepository cityRepository) {
		this.eventRepository = eventRepository;
		this.cityRepository = cityRepository;
	}

	@Transactional(readOnly = true)
	public Page<EventDTO> findAll(Pageable pageable) {
		return eventRepository.findAll(pageable).map(EventDTO::new);
	}

	@Transactional
	public EventDTO insert(EventDTO dto) {
		Event entity = new Event();
		copyDtoToEntity(dto, entity);
		entity = eventRepository.save(entity);
		return new EventDTO(entity);
	}

	private void copyDtoToEntity(EventDTO dto, Event entity) {
		entity.setName(dto.getName());
		entity.setDate(dto.getDate());
		entity.setUrl(dto.getUrl());
		City city = cityRepository.findById(dto.getCityId())
				.orElseThrow(() -> new EntityNotFoundException("City not found"));
		entity.setCity(city);
	}
}

