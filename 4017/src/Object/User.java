package Object;

public class User {

	private String Name;
	private String ID;
	private String Password;
	private String Remark;


	public String getName() {
		return Name;
	}

	public User setName(String Name) {
		this.Name = Name;
		return this;
	}

	public String getID() {
		return ID;
	}

	public User setID(String ID) {
		this.ID = ID;
		return this;
	}

	public String getPassword() {
		return Password;
	}

	public User setPassword(String Password) {
		this.Password = Password;
		return this;
	}

	public String getRemark() {
		return Remark;
	}

	public User setRemark(String Remark) {
		this.Remark = Remark;
		return this;
	}

}