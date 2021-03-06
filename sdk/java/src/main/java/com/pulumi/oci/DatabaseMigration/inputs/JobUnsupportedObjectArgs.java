// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseMigration.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class JobUnsupportedObjectArgs extends com.pulumi.resources.ResourceArgs {

    public static final JobUnsupportedObjectArgs Empty = new JobUnsupportedObjectArgs();

    /**
     * Name of the object (regular expression is allowed)
     * 
     */
    @Import(name="object")
    private @Nullable Output<String> object;

    /**
     * @return Name of the object (regular expression is allowed)
     * 
     */
    public Optional<Output<String>> object() {
        return Optional.ofNullable(this.object);
    }

    /**
     * Owner of the object (regular expression is allowed)
     * 
     */
    @Import(name="owner")
    private @Nullable Output<String> owner;

    /**
     * @return Owner of the object (regular expression is allowed)
     * 
     */
    public Optional<Output<String>> owner() {
        return Optional.ofNullable(this.owner);
    }

    /**
     * Type of unsupported object
     * 
     */
    @Import(name="type")
    private @Nullable Output<String> type;

    /**
     * @return Type of unsupported object
     * 
     */
    public Optional<Output<String>> type() {
        return Optional.ofNullable(this.type);
    }

    private JobUnsupportedObjectArgs() {}

    private JobUnsupportedObjectArgs(JobUnsupportedObjectArgs $) {
        this.object = $.object;
        this.owner = $.owner;
        this.type = $.type;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(JobUnsupportedObjectArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private JobUnsupportedObjectArgs $;

        public Builder() {
            $ = new JobUnsupportedObjectArgs();
        }

        public Builder(JobUnsupportedObjectArgs defaults) {
            $ = new JobUnsupportedObjectArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param object Name of the object (regular expression is allowed)
         * 
         * @return builder
         * 
         */
        public Builder object(@Nullable Output<String> object) {
            $.object = object;
            return this;
        }

        /**
         * @param object Name of the object (regular expression is allowed)
         * 
         * @return builder
         * 
         */
        public Builder object(String object) {
            return object(Output.of(object));
        }

        /**
         * @param owner Owner of the object (regular expression is allowed)
         * 
         * @return builder
         * 
         */
        public Builder owner(@Nullable Output<String> owner) {
            $.owner = owner;
            return this;
        }

        /**
         * @param owner Owner of the object (regular expression is allowed)
         * 
         * @return builder
         * 
         */
        public Builder owner(String owner) {
            return owner(Output.of(owner));
        }

        /**
         * @param type Type of unsupported object
         * 
         * @return builder
         * 
         */
        public Builder type(@Nullable Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type Type of unsupported object
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
        }

        public JobUnsupportedObjectArgs build() {
            return $;
        }
    }

}
