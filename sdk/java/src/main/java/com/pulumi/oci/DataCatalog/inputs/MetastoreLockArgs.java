// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataCatalog.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class MetastoreLockArgs extends com.pulumi.resources.ResourceArgs {

    public static final MetastoreLockArgs Empty = new MetastoreLockArgs();

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
     * The id of the resource that is locking this resource. Indicates that deleting this resource will remove the lock.
     * 
     */
    @Import(name="relatedResourceId")
    private @Nullable Output<String> relatedResourceId;

    /**
     * @return The id of the resource that is locking this resource. Indicates that deleting this resource will remove the lock.
     * 
     */
    public Optional<Output<String>> relatedResourceId() {
        return Optional.ofNullable(this.relatedResourceId);
    }

    /**
     * Time at which the metastore was created. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return Time at which the metastore was created. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * Type of the lock.
     * 
     */
    @Import(name="type")
    private @Nullable Output<String> type;

    /**
     * @return Type of the lock.
     * 
     */
    public Optional<Output<String>> type() {
        return Optional.ofNullable(this.type);
    }

    private MetastoreLockArgs() {}

    private MetastoreLockArgs(MetastoreLockArgs $) {
        this.message = $.message;
        this.relatedResourceId = $.relatedResourceId;
        this.timeCreated = $.timeCreated;
        this.type = $.type;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(MetastoreLockArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private MetastoreLockArgs $;

        public Builder() {
            $ = new MetastoreLockArgs();
        }

        public Builder(MetastoreLockArgs defaults) {
            $ = new MetastoreLockArgs(Objects.requireNonNull(defaults));
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
         * @param relatedResourceId The id of the resource that is locking this resource. Indicates that deleting this resource will remove the lock.
         * 
         * @return builder
         * 
         */
        public Builder relatedResourceId(@Nullable Output<String> relatedResourceId) {
            $.relatedResourceId = relatedResourceId;
            return this;
        }

        /**
         * @param relatedResourceId The id of the resource that is locking this resource. Indicates that deleting this resource will remove the lock.
         * 
         * @return builder
         * 
         */
        public Builder relatedResourceId(String relatedResourceId) {
            return relatedResourceId(Output.of(relatedResourceId));
        }

        /**
         * @param timeCreated Time at which the metastore was created. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated Time at which the metastore was created. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
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
        public Builder type(@Nullable Output<String> type) {
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

        public MetastoreLockArgs build() {
            return $;
        }
    }

}
