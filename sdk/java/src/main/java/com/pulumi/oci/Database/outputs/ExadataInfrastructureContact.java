// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class ExadataInfrastructureContact {
    /**
     * @return (Updatable) The email for the Exadata Infrastructure contact.
     * 
     */
    private String email;
    /**
     * @return (Updatable) If `true`, this Exadata Infrastructure contact is a valid My Oracle Support (MOS) contact. If `false`, this Exadata Infrastructure contact is not a valid MOS contact.
     * 
     */
    private @Nullable Boolean isContactMosValidated;
    /**
     * @return (Updatable) If `true`, this Exadata Infrastructure contact is a primary contact. If `false`, this Exadata Infrastructure is a secondary contact.
     * 
     */
    private Boolean isPrimary;
    /**
     * @return (Updatable) The name of the Exadata Infrastructure contact.
     * 
     */
    private String name;
    /**
     * @return (Updatable) The phone number for the Exadata Infrastructure contact.
     * 
     */
    private @Nullable String phoneNumber;

    private ExadataInfrastructureContact() {}
    /**
     * @return (Updatable) The email for the Exadata Infrastructure contact.
     * 
     */
    public String email() {
        return this.email;
    }
    /**
     * @return (Updatable) If `true`, this Exadata Infrastructure contact is a valid My Oracle Support (MOS) contact. If `false`, this Exadata Infrastructure contact is not a valid MOS contact.
     * 
     */
    public Optional<Boolean> isContactMosValidated() {
        return Optional.ofNullable(this.isContactMosValidated);
    }
    /**
     * @return (Updatable) If `true`, this Exadata Infrastructure contact is a primary contact. If `false`, this Exadata Infrastructure is a secondary contact.
     * 
     */
    public Boolean isPrimary() {
        return this.isPrimary;
    }
    /**
     * @return (Updatable) The name of the Exadata Infrastructure contact.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return (Updatable) The phone number for the Exadata Infrastructure contact.
     * 
     */
    public Optional<String> phoneNumber() {
        return Optional.ofNullable(this.phoneNumber);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ExadataInfrastructureContact defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String email;
        private @Nullable Boolean isContactMosValidated;
        private Boolean isPrimary;
        private String name;
        private @Nullable String phoneNumber;
        public Builder() {}
        public Builder(ExadataInfrastructureContact defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.email = defaults.email;
    	      this.isContactMosValidated = defaults.isContactMosValidated;
    	      this.isPrimary = defaults.isPrimary;
    	      this.name = defaults.name;
    	      this.phoneNumber = defaults.phoneNumber;
        }

        @CustomType.Setter
        public Builder email(String email) {
            if (email == null) {
              throw new MissingRequiredPropertyException("ExadataInfrastructureContact", "email");
            }
            this.email = email;
            return this;
        }
        @CustomType.Setter
        public Builder isContactMosValidated(@Nullable Boolean isContactMosValidated) {

            this.isContactMosValidated = isContactMosValidated;
            return this;
        }
        @CustomType.Setter
        public Builder isPrimary(Boolean isPrimary) {
            if (isPrimary == null) {
              throw new MissingRequiredPropertyException("ExadataInfrastructureContact", "isPrimary");
            }
            this.isPrimary = isPrimary;
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("ExadataInfrastructureContact", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder phoneNumber(@Nullable String phoneNumber) {

            this.phoneNumber = phoneNumber;
            return this;
        }
        public ExadataInfrastructureContact build() {
            final var _resultValue = new ExadataInfrastructureContact();
            _resultValue.email = email;
            _resultValue.isContactMosValidated = isContactMosValidated;
            _resultValue.isPrimary = isPrimary;
            _resultValue.name = name;
            _resultValue.phoneNumber = phoneNumber;
            return _resultValue;
        }
    }
}
