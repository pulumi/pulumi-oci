// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetExadataInfrastructuresFilter extends com.pulumi.resources.InvokeArgs {

    public static final GetExadataInfrastructuresFilter Empty = new GetExadataInfrastructuresFilter();

    /**
     * Name of the month of the year.
     * 
     */
    @Import(name="name", required=true)
    private String name;

    /**
     * @return Name of the month of the year.
     * 
     */
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

    private GetExadataInfrastructuresFilter() {}

    private GetExadataInfrastructuresFilter(GetExadataInfrastructuresFilter $) {
        this.name = $.name;
        this.regex = $.regex;
        this.values = $.values;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetExadataInfrastructuresFilter defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetExadataInfrastructuresFilter $;

        public Builder() {
            $ = new GetExadataInfrastructuresFilter();
        }

        public Builder(GetExadataInfrastructuresFilter defaults) {
            $ = new GetExadataInfrastructuresFilter(Objects.requireNonNull(defaults));
        }

        /**
         * @param name Name of the month of the year.
         * 
         * @return builder
         * 
         */
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

        public GetExadataInfrastructuresFilter build() {
            if ($.name == null) {
                throw new MissingRequiredPropertyException("GetExadataInfrastructuresFilter", "name");
            }
            if ($.values == null) {
                throw new MissingRequiredPropertyException("GetExadataInfrastructuresFilter", "values");
            }
            return $;
        }
    }

}
