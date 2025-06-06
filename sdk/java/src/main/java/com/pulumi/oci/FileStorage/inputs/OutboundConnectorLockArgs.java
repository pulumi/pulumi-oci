// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FileStorage.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class OutboundConnectorLockArgs extends com.pulumi.resources.ResourceArgs {

    public static final OutboundConnectorLockArgs Empty = new OutboundConnectorLockArgs();

    /**
     * A message added by the creator of the lock. This is typically used to give an indication of why the resource is locked.
     * 
     */
    @Import(name="message")
    private @Nullable Output<String> message;

    /**
     * @return A message added by the creator of the lock. This is typically used to give an indication of why the resource is locked.
     * 
     */
    public Optional<Output<String>> message() {
        return Optional.ofNullable(this.message);
    }

    /**
     * The ID of the resource that is locking this resource. Indicates that deleting this resource will remove the lock.
     * 
     */
    @Import(name="relatedResourceId")
    private @Nullable Output<String> relatedResourceId;

    /**
     * @return The ID of the resource that is locking this resource. Indicates that deleting this resource will remove the lock.
     * 
     */
    public Optional<Output<String>> relatedResourceId() {
        return Optional.ofNullable(this.relatedResourceId);
    }

    /**
     * When the lock was created.
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return When the lock was created.
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * Type of the lock.
     * 
     */
    @Import(name="type", required=true)
    private Output<String> type;

    /**
     * @return Type of the lock.
     * 
     */
    public Output<String> type() {
        return this.type;
    }

    private OutboundConnectorLockArgs() {}

    private OutboundConnectorLockArgs(OutboundConnectorLockArgs $) {
        this.message = $.message;
        this.relatedResourceId = $.relatedResourceId;
        this.timeCreated = $.timeCreated;
        this.type = $.type;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(OutboundConnectorLockArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private OutboundConnectorLockArgs $;

        public Builder() {
            $ = new OutboundConnectorLockArgs();
        }

        public Builder(OutboundConnectorLockArgs defaults) {
            $ = new OutboundConnectorLockArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param message A message added by the creator of the lock. This is typically used to give an indication of why the resource is locked.
         * 
         * @return builder
         * 
         */
        public Builder message(@Nullable Output<String> message) {
            $.message = message;
            return this;
        }

        /**
         * @param message A message added by the creator of the lock. This is typically used to give an indication of why the resource is locked.
         * 
         * @return builder
         * 
         */
        public Builder message(String message) {
            return message(Output.of(message));
        }

        /**
         * @param relatedResourceId The ID of the resource that is locking this resource. Indicates that deleting this resource will remove the lock.
         * 
         * @return builder
         * 
         */
        public Builder relatedResourceId(@Nullable Output<String> relatedResourceId) {
            $.relatedResourceId = relatedResourceId;
            return this;
        }

        /**
         * @param relatedResourceId The ID of the resource that is locking this resource. Indicates that deleting this resource will remove the lock.
         * 
         * @return builder
         * 
         */
        public Builder relatedResourceId(String relatedResourceId) {
            return relatedResourceId(Output.of(relatedResourceId));
        }

        /**
         * @param timeCreated When the lock was created.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated When the lock was created.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param type Type of the lock.
         * 
         * @return builder
         * 
         */
        public Builder type(Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type Type of the lock.
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
        }

        public OutboundConnectorLockArgs build() {
            if ($.type == null) {
                throw new MissingRequiredPropertyException("OutboundConnectorLockArgs", "type");
            }
            return $;
        }
    }

}
