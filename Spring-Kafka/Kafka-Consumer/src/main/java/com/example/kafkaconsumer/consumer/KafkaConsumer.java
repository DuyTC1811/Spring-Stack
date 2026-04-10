package com.example.kafkaconsumer.consumer;

import lombok.extern.slf4j.Slf4j;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class KafkaConsumer {

    @KafkaListener(topics = "pgserver.public.users", groupId = "0")
    public void consumer(ConsumerRecord<String, String> record) {
        log.info("[ RECEIVED-MESSAGE ]: [ TOPIC - {} ] , [ PARTITION - {} ], [ OFFSET - {} ], [ KEY - {} ], [ VALUE ] = {}",
                record.topic(), record.partition(), record.offset(), record.key(), record.value());
    }
}
