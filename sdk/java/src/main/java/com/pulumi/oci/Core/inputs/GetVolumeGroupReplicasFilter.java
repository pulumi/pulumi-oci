// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetVolumeGroupReplicasFilter extends com.pulumi.resources.InvokeArgs {

    public static final GetVolumeGroupReplicasFilter Empty = new GetVolumeGroupReplicasFilter();

    @Import(name="name", required=true)
    private String name;

    public String name() {
        return this.name;
    }

    @Import(name="regex")
    private @Nullable Boolean regex;

    public Optional<Boolean> regex() {
        return Optional.ofNullable(this.regex);
    }

    @Import(name="values", required=true)
    private List<String> values;

    public List<String> values() {
        return this.values;
    }

    private GetVolumeGroupReplicasFilter() {}

    private GetVolumeGroupReplicasFilter(GetVolumeGroupReplicasFilter $) {
        this.name = $.name;
        this.regex = $.regex;
        this.values = $.values;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetVolumeGroupReplicasFilter defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetVolumeGroupReplicasFilter $;

        public Builder() {
            $ = new GetVolumeGroupReplicasFilter();
        }

        public Builder(GetVolumeGroupReplicasFilter defaults) {
            $ = new GetVolumeGroupReplicasFilter(Objects.requireNonNull(defaults));
        }

        public Builder name(String name) {
            $.name = name;
            return this;
        }

        public Builder regex(@Nullable Boolean regex) {
            $.regex = regex;
            return this;
        }

        public Builder values(List<String> values) {
            $.values = values;
            return this;
        }

        public Builder values(String... values) {
            return values(List.of(values));
        }

        public GetVolumeGroupReplicasFilter build() {
            if ($.name == null) {
                throw new MissingRequiredPropertyException("GetVolumeGroupReplicasFilter", "name");
            }
            if ($.values == null) {
                throw new MissingRequiredPropertyException("GetVolumeGroupReplicasFilter", "values");
            }
            return $;
        }
    }

}
