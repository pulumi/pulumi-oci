// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Sch.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ConnectorSourceCursorArgs extends com.pulumi.resources.ResourceArgs {

    public static final ConnectorSourceCursorArgs Empty = new ConnectorSourceCursorArgs();

    /**
     * (Updatable) The type descriminator.
     * 
     */
    @Import(name="kind")
    private @Nullable Output<String> kind;

    /**
     * @return (Updatable) The type descriminator.
     * 
     */
    public Optional<Output<String>> kind() {
        return Optional.ofNullable(this.kind);
    }

    private ConnectorSourceCursorArgs() {}

    private ConnectorSourceCursorArgs(ConnectorSourceCursorArgs $) {
        this.kind = $.kind;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ConnectorSourceCursorArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ConnectorSourceCursorArgs $;

        public Builder() {
            $ = new ConnectorSourceCursorArgs();
        }

        public Builder(ConnectorSourceCursorArgs defaults) {
            $ = new ConnectorSourceCursorArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param kind (Updatable) The type descriminator.
         * 
         * @return builder
         * 
         */
        public Builder kind(@Nullable Output<String> kind) {
            $.kind = kind;
            return this;
        }

        /**
         * @param kind (Updatable) The type descriminator.
         * 
         * @return builder
         * 
         */
        public Builder kind(String kind) {
            return kind(Output.of(kind));
        }

        public ConnectorSourceCursorArgs build() {
            return $;
        }
    }

}