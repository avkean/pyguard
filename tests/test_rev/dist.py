FLAG = "EC3{REDACTED}"
wins = 0

print("Win 3 rounds in a row to get the flag!")

while wins < 3:
    user = input("Choose rock, paper, or scissors: ").lower()
    
    if user not in ["rock", "paper", "scissors"]:
        print("Invalid input.")
        continue
        
    if wins < 2:
        if user == "rock":
            comp = "scissors"
        elif user == "paper":
            comp = "rock"
        else:
            comp = "paper"
            
        print(f"Computer chose {comp}. You win!")
        wins += 1
    else:
        if user == "rock":
            comp = "paper"
        elif user == "paper":
            comp = "scissors"
        else:
            comp = "rock"
            
        print(f"Computer chose {comp}. You lose! Streak reset.")
        wins = 0

print(f"Congratulations! {FLAG}")
